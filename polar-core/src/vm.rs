use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt::Write;
use std::rc::Rc;
use std::string::ToString;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use crate::{
    bindings::{BindingManager, BindingStack, Bindings, Bsp, FollowerId, Lookup, VariableState},
    counter::Counter,
    data_filtering::partition_equivs,
    debugger::{DebugEvent, Debugger},
    error::{ErrorKind, PolarError, PolarResult, RuntimeError},
    events::*,
    folder::Folder,
    formatting::ToPolarString,
    inverter::Inverter,
    kb::*,
    lexer::loc_to_pos,
    messages::*,
    partial::{simplify_bindings, simplify_partial, sub_this, IsaConstraintCheck},
    rewrites::Renamer,
    rules::*,
    runnable::Runnable,
    sources::*,
    terms::*,
    traces::*,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

const MAX_STACK_SIZE: usize = 10_000;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone)]
#[must_use = "ignored goals are never accomplished"]
#[allow(clippy::large_enum_variant)]
pub enum Goal {
    Backtrack,
    Cut(usize), // cuts all choices in range [choice_index..]
    Debug(String),
    Error(PolarError),
    Halt,
    Isa(Term, Term),
    IsMoreSpecific {
        left: Arc<Rule>,
        right: Arc<Rule>,
        args: TermList,
    },
    IsSubspecializer {
        answer: Symbol,
        left: Term,
        right: Term,
        arg: Term,
    },
    Lookup {
        dict: Dictionary,
        field: Term,
        value: Term,
    },
    LookupExternal {
        call_id: u64,
        instance: Term,
        field: Term,
    },
    IsaExternal {
        instance: Term,
        literal: InstanceLiteral,
    },
    MakeExternal {
        constructor: Term,
        instance_id: u64,
    },
    NextExternal {
        call_id: u64,
        iterable: Term,
    },
    CheckError,
    Noop,
    Query(Term),
    PopQuery(Term),
    CallRules(Rules, TermList),
    TraceRule(Rc<Trace>),
    TraceStackPush,
    TraceStackPop,
    Unify(Term, Term),

    /// Run the `runnable`.
    Run(Box<dyn Runnable>),

    /// Add a new constraint
    AddConstraint(Term),

    /// TODO hack.
    /// Add a new constraint
    AddConstraintsBatch(Rc<RefCell<Bindings>>),
}

#[derive(Clone, Debug)]
pub struct Choice {
    pub alternatives: Vec<GoalStack>,
    bsp: Bsp,              // binding stack pointer
    pub goals: GoalStack,  // goal stack snapshot
    queries: Vec<Term>,    // query stack snapshot
    trace: Vec<Rc<Trace>>, // trace snapshot
    trace_stack: Vec<Vec<Rc<Trace>>>,
}

/// Shortcut type alias for a list of goals
#[derive(Clone, Debug, Default)]
pub struct GoalStack(pub Vec<Rc<Goal>>);

impl GoalStack {
    pub fn new_reversed(goals: Vec<Goal>) -> Self {
        Self(goals.into_iter().rev().map(Rc::new).collect())
    }
}

impl std::ops::Deref for GoalStack {
    type Target = Vec<Rc<Goal>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for GoalStack {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone)]
pub struct PolarVirtualMachine {
    /// Stacks.
    pub goals: GoalStack,
    pub substitution: BindingManager,
    pub choices: Vec<Choice>,
    pub queries: Vec<Term>,

    pub tracing: bool,
    pub trace_stack: Vec<Vec<Rc<Trace>>>, // Stack of traces higher up the tree.
    pub trace: Vec<Rc<Trace>>,            // Traces for the current level of the trace tree.

    // Errors from outside the vm.
    pub external_error: Option<String>,

    /// Maximum size of goal stack
    pub stack_limit: usize,

    /// Binding stack constant below here.
    pub csp: Bsp,

    /// Interactive debugger.
    pub debugger: Debugger,

    /// Rules and types.
    pub kb: Arc<RwLock<KnowledgeBase>>,

    /// Call ID -> result variable name table.
    pub calls: HashMap<u64, Symbol>,

    /// Logging flag.
    pub log: bool,
    pub polar_log: bool,
    pub polar_log_stderr: bool,
    pub polar_log_mute: bool,

    // Other flags.
    pub inverting: bool,

    /// Output messages.
    pub messages: MessageQueue,

    pub counter: Counter,

    #[cfg(not(target_arch = "wasm32"))]
    pub query_start_time: Option<std::time::Instant>,
    #[cfg(target_arch = "wasm32")]
    pub query_start_time: Option<f64>,
    pub query_timeout_ms: u64,
}

impl Default for PolarVirtualMachine {
    fn default() -> Self {
        let log = env::var("RUST_LOG").is_ok();
        let polar_log = env::var("POLAR_LOG")
            .ok()
            .map_or(false, |s| !(s == "0" || s == "off"));
        let polar_log_stderr = env::var("POLAR_LOG").ok().map_or(false, |s| s == "now");
        let query_timeout_ms = env::var("POLAR_TIMEOUT_MS")
            .ok()
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let mut vm = Self {
            stack_limit: MAX_STACK_SIZE,
            log,
            polar_log,
            polar_log_stderr,
            query_timeout_ms,
            goals: GoalStack::default(),
            kb: Arc::default(),
            messages: MessageQueue::default(),
            substitution: BindingManager::default(),
            csp: Bsp::default(),
            debugger: Debugger::default(),
            counter: Counter::default(),
            calls: HashMap::default(),
            choices: vec![],
            queries: vec![],
            trace_stack: vec![],
            trace: vec![],
            query_start_time: None,
            external_error: None,
            tracing: false,
            polar_log_mute: false,
            inverting: false,
        };
        let consts = vm.kb().constants.clone();
        for (var, val) in consts.into_iter() {
            vm.substitution.add_binding(&var, val);
        }
        vm.csp = vm.substitution.bsp();
        vm
    }
}

// Methods which aren't goals/instructions.
impl PolarVirtualMachine {
    fn start_query(&mut self) -> PolarResult<QueryEvent> {
        if self.query_start_time.is_none() {
            #[cfg(not(target_arch = "wasm32"))]
            let query_start_time = Some(std::time::Instant::now());
            #[cfg(target_arch = "wasm32")]
            let query_start_time = Some(js_sys::Date::now());
            self.query_start_time = query_start_time;
        }
        self.do_goals()
    }

    fn backtrack(&mut self) -> PolarResult<&mut Self> {
        match self.choices.pop() {
            None => self.goal(Goal::Halt),
            Some(mut ch) => {
                self.substitution.backtrack(&ch.bsp);
                match ch.alternatives.pop() {
                    None => self.backtrack(),
                    Some(GoalStack(mut alt)) => {
                        if ch.alternatives.is_empty() {
                            self.goals = ch.goals;
                            self.queries = ch.queries;
                            self.trace = ch.trace;
                            self.trace_stack = ch.trace_stack;
                        } else {
                            self.goals.clone_from(&ch.goals);
                            self.queries.clone_from(&ch.queries);
                            self.trace.clone_from(&ch.trace);
                            self.trace_stack.clone_from(&ch.trace_stack);
                            self.choices.push(ch)
                        }
                        self.goals.append(&mut alt);
                        Ok(self)
                    }
                }
            }
        }
    }

    fn rust_log(&mut self, f: &str) -> &mut Self {
        if self.log {
            self.print(f)
        }
        self
    }

    fn polar_log(&mut self, msg: &str, terms: &[&Term]) -> &mut Self {
        self.log_with(|| msg, terms);
        self
    }

    fn go_back(&mut self) -> PolarResult<&mut Self> {
        self.rust_log("⇒ backtrack")
            .polar_log("BACKTRACK", &[])
            .backtrack()
    }

    fn do_goals(&mut self) -> PolarResult<QueryEvent> {
        if !self.goals.is_empty() {
            self.next_goal()
        } else if !self.choices.is_empty() {
            self.go_back()?.do_goals()
        } else {
            Ok(QueryEvent::Done(true))
        }
    }

    fn done_with(&mut self, g: Rc<Goal>) -> PolarResult<QueryEvent> {
        self.debug_event(DebugEvent::Goal(g))?.next_goal()
    }

    fn next_goal(&mut self) -> PolarResult<QueryEvent> {
        match self.goals.pop() {
            None => self.finish_up(),
            Some(goal) => {
                match self.run_goal(goal.clone()) {
                    Ok(QueryEvent::None) => self.done_with(goal),
                    Err(PolarError {
                        kind: ErrorKind::Control,
                        ..
                    }) => self.go_back()?.do_goals(),
                    Err(error) =>
                    // if we pushed a debug goal, push an error goal underneath it.
                    {
                        self.debug_event(DebugEvent::Error(error))?
                            .next_goal()
                    }
                    result => {
                        self.external_error = None;
                        result
                    }
                }
            }
        }
    }

    fn finish_up(&mut self) -> PolarResult<QueryEvent> {
        if self.log {
            self.print("⇒ result");
            if self.tracing {
                for t in &self.trace {
                    self.print(&format!("trace\n{}", t.draw(self)));
                }
            }
        }

        let trace = self.tracing.then(|| ()).and_then(|_| {
            self.trace.first().cloned().map(|trace| TraceResult {
                formatted: trace.draw(self),
                trace,
            })
        });

        let all_done = |bindings| Ok(QueryEvent::Result { trace, bindings });
        let bindings = self.bindings(true);
        match self.inverting {
            true => all_done(bindings),
            false => match simplify_bindings(bindings, false) {
                None => self.done(),
                Some(bindings) => all_done(
                    bindings
                        .iter()
                        .filter_map(|(var, value)| {
                            (!var.is_temporary_var())
                                .then(|| (var.clone(), sub_this(var.clone(), value.clone())))
                        })
                        .collect(),
                ),
            },
        }
    }

    /// Try to achieve one goal. Return `Some(QueryEvent)` if an external
    /// result is needed to achieve it, or `None` if it can run internally.
    fn run_goal(&mut self, goal: Rc<Goal>) -> PolarResult<QueryEvent> {
        if self.log {
            self.print(&format!("{}", goal));
        }

        if self.query_timeout_ms != 0 {
            let elapsed = self.query_duration();
            if elapsed > self.query_timeout_ms {
                return self.err(RuntimeError::QueryTimeout {
                    msg: format!(
                        "Query running for {}ms, which exceeds the timeout of {}ms. To disable timeouts, set the POLAR_TIMEOUT_MS environment variable to 0.",
                        elapsed, self.query_timeout_ms), });
            }
        }

        match goal.as_ref() {
            Goal::Backtrack => Self::nope(),
            Goal::Noop => self.done_with(goal),
            Goal::Debug(message) => self.debug(message),
            Goal::Halt => self.halt(),
            Goal::Error(error) => Err(error.clone()),
            Goal::Unify(left, right) => self.unify(left, right)?.done_with(goal),
            Goal::Isa(left, right) => self.isa(left, right)?.done_with(goal),
            Goal::IsMoreSpecific { left, right, args } => {
                self.is_more_specific(left, right, args)?.done_with(goal)
            }
            Goal::Cut(choice_index) => {
                self.choices.truncate(*choice_index);
                self.done_with(goal)
            }
            Goal::Lookup { dict, field, value } => self.lookup(dict, field, value)?.done_with(goal),
            Goal::IsSubspecializer {
                answer,
                left,
                right,
                arg,
            } => self.is_subspecializer(answer, left, right, arg),
            Goal::LookupExternal {
                call_id,
                instance,
                field,
            } => self.lookup_external(*call_id, instance, field),
            Goal::IsaExternal { instance, literal } => {
                let (call_id, answer) = self.new_call_var("isa", false.into());
                self.goal(Goal::Unify(answer, Term::from(true)))?;
                Ok(QueryEvent::ExternalIsa {
                    call_id,
                    instance: self.deref(instance),
                    class_tag: literal.tag.clone(),
                })
            }
            Goal::MakeExternal {
                constructor,
                instance_id,
            } => Ok(QueryEvent::MakeExternal {
                instance_id: *instance_id,
                constructor: self.deref(constructor),
            }),
            Goal::NextExternal { call_id, iterable } => {
                // add another choice point for the next result
                self.push_choice(vec![vec![Goal::NextExternal {
                    call_id: *call_id,
                    iterable: iterable.clone(),
                }]]);
                Ok(QueryEvent::NextExternal {
                    call_id: *call_id,
                    iterable: iterable.clone(),
                })
            }
            Goal::CheckError => self.external_error.as_ref().map_or(Self::yes(), |e| {
                let e = RuntimeError::Application {
                    msg: e.clone(),
                    stack_trace: Some(self.stack_trace()),
                };
                match self.trace.last().map(|t| t.node.clone()) {
                    Some(Node::Term(t)) => self.err_ctx(&t, e),
                    _ => self.err(e),
                }
            }),
            Goal::Query(term) => {
                let result = self.query(term);
                self.debug_event(DebugEvent::Query)?;
                result
            }
            Goal::PopQuery(_) => {
                self.queries.pop();
                self.done_with(goal)
            }
            Goal::CallRules(rules, args) => self.call_rules(rules, args)?.done(),
            Goal::TraceStackPush => {
                self.trace_stack.push(self.trace.clone());
                self.trace = vec![];
                self.done_with(goal)
            }
            Goal::TraceStackPop => {
                let mut children = self.trace.clone();
                self.trace = self.trace_stack.pop().unwrap_or_else(Vec::new);
                let mut trace = self.trace.pop().unwrap();
                let trace = Rc::make_mut(&mut trace);
                trace.children.append(&mut children);
                self.trace.push(Rc::new(trace.clone()));
                self.debug_event(DebugEvent::Pop)?.done_with(goal)
            }
            Goal::TraceRule(trace) => {
                if let Node::Rule(rule) = &trace.node {
                    self.log_with(|| format!("RULE: {}", rule.to_polar()), &[]);
                }
                self.trace.push(trace.clone());
                self.debug_event(DebugEvent::Rule)?.done_with(goal)
            }
            Goal::AddConstraint(term) => self.add_constraint(term)?.done_with(goal),
            Goal::AddConstraintsBatch(add_constraints) => add_constraints
                .clone()
                .borrow_mut()
                .drain()
                .fold(Ok(self), |this, (_, constraint)| {
                    this?.add_constraint(&constraint)
                })?
                .done_with(goal),
            Goal::Run(runnable) => {
                let runnable = runnable.clone_runnable();
                let (call_id, answer) = self.new_call_var("runnable_result", Value::Boolean(false));
                self.goal(Goal::Unify(answer, Term::from(true)))?;
                Ok(QueryEvent::Run { runnable, call_id })
            }
        }
    }

    /// Push a goal onto the goal stack.
    fn goal(&mut self, goal: Goal) -> PolarResult<&mut Self> {
        if self.goals.len() >= self.stack_limit {
            return self.err(RuntimeError::StackOverflow {
                msg: format!("Goal stack overflow! MAX_GOALS = {}", self.stack_limit),
            });
        }
        match goal {
            Goal::LookupExternal { call_id, .. } | Goal::NextExternal { call_id, .. } => {
                assert!(matches!(
                    self.variable_state(self.calls.get(&call_id).unwrap()),
                    None
                ), "The call_id result variables for LookupExternal and NextExternal goals must be unbound.");
            }
            _ => (),
        }

        self.goals.push(Rc::new(goal));
        Ok(self)
    }

    fn push_choice<I>(&mut self, alternatives: I) -> &mut Self
    where
        I: IntoIterator<Item = Vec<Goal>>,
        I::IntoIter: std::iter::DoubleEndedIterator,
    {
        // Make sure that alternatives are executed in order of first to last.
        let alternatives = alternatives
            .into_iter()
            .rev()
            .map(GoalStack::new_reversed)
            .collect();
        self.choices.push(Choice {
            alternatives,
            bsp: self.substitution.bsp(),
            goals: self.goals.clone(),
            queries: self.queries.clone(),
            trace: self.trace.clone(),
            trace_stack: self.trace_stack.clone(),
        });
        assert!(self.choices.len() < self.stack_limit, "too many choices");
        self
    }

    /// Push a choice onto the choice stack, and execute immediately by
    /// pushing the first alternative onto the goals stack
    ///
    /// Params:
    ///
    /// - `alternatives`: an ordered list of alternatives to try in the choice.
    ///   The first element is the first alternative to try.
    fn choose<I>(&mut self, alternatives: I) -> PolarResult<&mut Self>
    where
        I: IntoIterator<Item = Vec<Goal>>,
        I::IntoIter: std::iter::DoubleEndedIterator,
    {
        let mut iter = alternatives.into_iter();
        iter.next().map_or_else(Self::nope, move |alt| self.push_choice(iter).append_goals(alt))
    }

    /// If each goal of `conditional` succeeds, execute `consequent`;
    /// otherwise, execute `alternative`. The branches are entered only
    /// by backtracking so that bindings established during the execution
    /// of `conditional` are always unwound.
    fn choose_conditional(
        &mut self,
        mut conditional: Vec<Goal>,
        consequent: Vec<Goal>,
        mut alternative: Vec<Goal>,
    ) -> PolarResult<&mut Self> {
        alternative.insert(0, Goal::Cut(self.choices.len()));
        self.push_choice(vec![consequent]);
        conditional.push(Goal::Cut(self.choices.len()));
        conditional.push(Goal::Backtrack);
        self.choose(vec![conditional, alternative])
    }

    /// Push multiple goals onto the stack in reverse order.
    fn append_goals<I>(&mut self, goals: I) -> PolarResult<&mut Self>
    where
        I: IntoIterator<Item = Goal>,
        I::IntoIter: std::iter::DoubleEndedIterator,
    {
        goals
            .into_iter()
            .rev()
            .fold(Ok(self), |this, g| this?.goal(g))
    }

    /// Rebind an external answer variable. Don't use for anything else.
    fn rebind_external_answer(&mut self, var: &Symbol, val: Term) -> &mut Self {
        self.substitution.add_binding(var, val);
        self
    }

    /// Push a binding onto the binding stack.
    pub fn bind(&mut self, var: &Term, val: Term) -> PolarResult<&mut Self> {
        if self.log {
            self.print(&format!("⇒ bind: {} ← {}", var.to_polar(), val.to_polar()));
        }
        match self.substitution.bind(var, val) {
            Ok(Some(goal)) => self.goal(goal),
            Ok(None) => Ok(self),
            Err(PolarError {
                kind: ErrorKind::Control,
                ..
            }) => self.go_back(),
            Err(e) => Err(e),
        }
    }

    pub fn add_binding_follower(&mut self) -> FollowerId {
        self.substitution.add_follower(Default::default())
    }

    pub fn remove_binding_follower(&mut self, follower_id: &FollowerId) -> Option<BindingManager> {
        self.substitution.remove_follower(follower_id)
    }

    /// Add a single constraint operation to the variables referenced in it.
    /// Precondition: Operation is either binary or ternary (binary + result var),
    /// and at least one of the first two arguments is an unbound variable.
    fn add_constraint(&mut self, term: &Term) -> PolarResult<&mut Self> {
        if self.log {
            self.print(&format!("⇒ add_constraint: {}", term.to_polar()));
        }
        self.substitution.add_constraint(term)?;
        Ok(self)
    }

    /// Retrieve the current non-constant bindings as a hash map.
    pub fn bindings(&self, include_temps: bool) -> Bindings {
        self.substitution.bindings_after(include_temps, &self.csp)
    }

    /// Retrive internal binding stack for debugger.
    pub fn bindings_debug(&self) -> &BindingStack {
        self.substitution.bindings_debug()
    }

    /// Returns bindings for all vars used by terms in terms.
    pub fn relevant_bindings(&self, terms: &[&Term]) -> Bindings {
        let mut variables = HashSet::new();
        for t in terms {
            t.variables(&mut variables);
        }
        self.substitution.variable_bindings(&variables)
    }

    pub fn get<'a>(&'a self, y: &'a Term) -> Option<Lookup<'a>> {
        self.substitution.get(y)
    }

    fn get_var(&self, variable: &Symbol) -> Option<Term> {
        match self.substitution.variable_state(variable) {
            Some(VariableState::Bound(t)) => Some(t),
            _ => None,
        }
    }
    /// Investigate the current state of a variable and return a variable state variant.
    fn variable_state(&self, variable: &Symbol) -> Option<VariableState> {
        self.substitution.variable_state(variable)
    }

    fn deref(&self, term: &Term) -> Term {
        self.substitution.deref(term)
    }

    /// Generate a fresh set of variables for a rule.
    fn rename_rule_vars(&self, rule: &Rule) -> Rule {
        let kb = &*self.kb();
        let mut renamer = Renamer::new(kb);
        renamer.fold_rule(rule.clone())
    }

    /// If the inner [`Debugger`](struct.Debugger.html) returns a [`Goal`](../vm/enum.Goal.html),
    /// push it onto the goal stack.
    pub fn debug_event(&mut self, event: DebugEvent) -> PolarResult<&mut Self> {
        let err = if let DebugEvent::Error(ref e) = event {
            Some(e.clone())
        } else {
            None
        };
        match self.break_maybe(event) {
            None => Ok(self),
            Some(goal) => if let Some(e) = err {
                self.goal(Goal::Error(e))?
            } else {
                self
            }
            .goal(goal),
        }
    }

    fn new_id(&self) -> u64 {
        self.kb().new_id()
    }

    fn new_call_id(&mut self, symbol: &Symbol) -> u64 {
        let call_id = self.new_id();
        self.calls.insert(call_id, symbol.clone());
        call_id
    }

    fn new_call_var(&mut self, var_prefix: &str, initial_value: Value) -> (u64, Term) {
        let var = Term::from(Value::Variable(self.kb().gensym(var_prefix)));
        self.bind(&var, Term::from(initial_value)).unwrap();
        let call_id = self.new_call_id(var.value().as_symbol().unwrap());
        (call_id, var)
    }

    fn log_with<F, R>(&self, message_fn: F, terms: &[&Term])
    where
        F: FnOnce() -> R,
        R: AsRef<str>,
    {
        if self.polar_log && !self.polar_log_mute {
            let mut indent = String::new();
            for _ in 0..=self.queries.len() {
                indent.push_str("  ");
            }
            let message = message_fn();
            let lines = message.as_ref().split('\n').collect::<Vec<&str>>();
            if let Some(line) = lines.first() {
                let mut msg = format!("[debug] {}{}", &indent, line);
                if !terms.is_empty() {
                    let relevant_bindings = self.relevant_bindings(terms);
                    msg.push_str(&format!(
                        ", BINDINGS: {{{}}}",
                        relevant_bindings
                            .iter()
                            .map(|(var, val)| format!("{} = {}", var.0, val.to_polar()))
                            .collect::<Vec<String>>()
                            .join(", ")
                    ));
                }
                self.print(msg);
                for line in &lines[1..] {
                    self.print(format!("[debug] {}{}", &indent, line));
                }
            }
        }
    }

    fn kb(&self) -> RwLockReadGuard<'_, KnowledgeBase> {
        self.kb.read().unwrap()
    }

    pub fn source(&self, term: &Term) -> Option<Source> {
        term.get_source_id()
            .and_then(|id| self.kb().sources.get_source(id))
    }

    /// Get the query stack as a string for printing in error messages.
    pub fn stack_trace(&self) -> String {
        let mut trace_stack = self.trace_stack.clone();
        let mut trace = self.trace.clone();

        // Build linear stack from trace tree. Not just using query stack because it doesn't
        // know about rules, query stack should really use this too.
        let mut stack = vec![];
        while let Some(t) = trace.last() {
            stack.push(t.clone());
            trace = trace_stack.pop().unwrap_or_else(Vec::new);
        }

        stack.reverse();

        let mut st = String::new();
        let _ = write!(st, "trace (most recent evaluation last):");

        let mut rule = None;
        for t in stack {
            match &t.node {
                Node::Rule(r) => {
                    rule = Some(r.clone());
                }
                Node::Term(t) => {
                    if matches!(t.value(), Value::Expression(Operation { operator: Operator::And, args}) if args.len() == 1)
                    {
                        continue;
                    }
                    let _ = write!(st, "\n  ");

                    if let Some(source) = self.source(t) {
                        if let Some(rule) = &rule {
                            let _ = write!(st, "in rule {} ", rule.name.to_polar());
                        } else {
                            let _ = write!(st, "in query ");
                        }
                        let (row, column) = loc_to_pos(&source.src, t.offset());
                        let _ = write!(st, "at line {}, column {}", row + 1, column + 1);
                        if let Some(filename) = source.filename {
                            let _ = write!(st, " in file {}", filename);
                        }
                        let _ = writeln!(st);
                    };
                    let _ = write!(st, "    {}", self.term_source(t, false));
                }
            }
        }
        st
    }

    /// Push or print a message to the output stream.
    #[cfg(not(target_arch = "wasm32"))]
    fn print<S: Into<String>>(&self, message: S) {
        let message = message.into();
        if self.polar_log_stderr {
            eprintln!("{}", message);
        } else {
            self.messages.push(MessageKind::Print, message);
        }
    }

    /// Push or print a message to the WASM output stream.
    #[cfg(target_arch = "wasm32")]
    fn print<S: Into<String>>(&self, message: S) {
        let message = message.into();
        if self.polar_log_stderr {
            console_error(&message);
        } else {
            self.messages.push(MessageKind::Print, message);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn query_duration(&self) -> u64 {
        let now = std::time::Instant::now();
        let start = self.query_start_time.expect("Query start not recorded");
        (now - start).as_millis() as u64
    }

    #[cfg(target_arch = "wasm32")]
    fn query_duration(&self) -> u64 {
        let now: f64 = js_sys::Date::now();
        let start = self.query_start_time.expect("Query start not recorded");
        (now - start) as u64
    }

    #[cfg(target_arch = "wasm32")]
    pub fn set_logging_options(&mut self, rust_log: Option<String>, polar_log: Option<String>) {
        self.log = rust_log.is_some();
        self.polar_log = match polar_log {
            None | Some("0") | Some("off") => false,
            Some(pl) => {
                if pl == "now" {
                    self.polar_log_stderr = true
                }
                true
            }
        }
    }

    /// Interact with the debugger.
    fn debug(&mut self, message: &str) -> PolarResult<QueryEvent> {
        // Query start time is reset when a debug event occurs.
        self.query_start_time = None;
        Ok(QueryEvent::Debug(message.to_string()))
    }

    /// Halt the VM by clearing all goals and choices.
    fn halt(&mut self) -> PolarResult<QueryEvent> {
        self.polar_log("HALT", &[]);
        self.goals.clear();
        self.choices.clear();
        Ok(QueryEvent::Done(true))
    }

    /// Comparison operator that essentially performs partial unification.
    #[allow(clippy::many_single_char_names)]
    pub fn isa(&mut self, left: &Term, right: &Term) -> PolarResult<&mut Self> {
        self.log_with(
            || format!("MATCHES: {} matches {}", left.to_polar(), right.to_polar()),
            &[left, right],
        );

        match (left.value(), right.value()) {
            (_, Value::Dictionary(_)) => unreachable!("parsed as pattern"),
            (Value::Expression(_), _) | (_, Value::Expression(_)) => {
                unreachable!("encountered bare expression")
            }

            _ if self.kb().is_union(left) => {
                // A union (currently) only matches itself.
                //
                // TODO(gj): when we have unions beyond `Actor` and `Resource`, we'll need to be
                // smarter about this check since UnionA is more specific than UnionB if UnionA is
                // a member of UnionB.
                let unions_match = (left.is_actor_union() && right.is_actor_union())
                    || (left.is_resource_union() && right.is_resource_union());
                self.maybe(unions_match)
            }
            _ if self.kb().is_union(right) => self.isa_union(left, right),

            // TODO(gj): (Var, Rest) + (Rest, Var) cases might be unreachable.
            (Value::Variable(l), Value::Variable(r))
            | (Value::Variable(l), Value::RestVariable(r))
            | (Value::RestVariable(l), Value::Variable(r))
            | (Value::RestVariable(l), Value::RestVariable(r)) => {
                // Two variables.
                match (self.get_var(l), self.get_var(r)) {
                    (Some(x), _) => self.goal(Goal::Isa(x, right.clone())),
                    (_, Some(y)) => self.goal(Goal::Isa(left.clone(), y)),
                    _ => self.add_constraint(&term!(op!(Isa, left.clone(), right.clone()))),
                }
            }

            (Value::Variable(l), _) | (Value::RestVariable(l), _) => match self.variable_state(l) {
                Some(VariableState::Bound(x)) => self.goal(Goal::Isa(x, right.clone())),
                Some(VariableState::Partial) => self.isa_expr(left, right),
                None => self.goal(Goal::Unify(left.clone(), right.clone())),
            },

            (_, Value::Variable(r)) | (_, Value::RestVariable(r)) => match self.get_var(r) {
                Some(y) => self.goal(Goal::Isa(left.clone(), y)),
                _ => self.goal(Goal::Unify(left.clone(), right.clone())),
            },

            (Value::List(left), Value::List(right)) => {
                self.uni_list(left, right, |(left, right)| {
                    Goal::Isa(left.clone(), right.clone())
                })
            }

            (Value::Dictionary(left), Value::Pattern(Pattern::Dictionary(right))) => {
                // Check that the left is more specific than the right.
                let lfs: HashSet<&Symbol> = left.fields.keys().collect();
                let rfs: HashSet<&Symbol> = right.fields.keys().collect();
                right
                    .fields
                    .iter()
                    .fold(self.maybe(rfs.is_subset(&lfs)), |s, (k, v)| {
                        let this = s?;
                        let left = left
                            .fields
                            .get(k)
                            .expect("left fields should be a superset of right fields")
                            .clone();
                        this.goal(Goal::Isa(left, v.clone()))
                    })
            }

            (_, Value::Pattern(Pattern::Dictionary(right))) => {
                right
                    .fields
                    .iter()
                    .fold(Ok(self), |s, (field, right_value)| {
                        let this = s?;
                        let answer = this.kb().gensym("isa_value");
                        let lookup = Goal::LookupExternal {
                            instance: left.clone(),
                            call_id: this.new_call_id(&answer),
                            field: right_value.clone_with_value(Value::String(field.0.clone())),
                        };
                        let isa = Goal::Isa(Term::from(answer), right_value.clone());
                        this.append_goals(vec![lookup, isa])
                    })
            }

            (_, Value::Pattern(Pattern::Instance(right_literal))) => {
                // Check fields
                self.goal(Goal::Isa(
                    left.clone(),
                    right.clone_with_value(Value::Pattern(Pattern::Dictionary(
                        right_literal.fields.clone(),
                    ))),
                ))?
                .goal(Goal::IsaExternal {
                    instance: left.clone(),
                    literal: right_literal.clone(),
                })
            }

            // Default case: x isa y if x = y.
            _ => self.goal(Goal::Unify(left.clone(), right.clone())),
        }
    }

    fn get_names(&self, s: &Symbol) -> HashSet<Symbol> {
        partition_equivs(
            self.substitution
                .get_constraints(s)
                .constraints()
                .into_iter()
                .filter_map(|con| match con.operator {
                    Operator::Unify | Operator::Eq => {
                        if let (Ok(l), Ok(r)) = (
                            con.args[0].value().as_symbol(),
                            con.args[1].value().as_symbol(),
                        ) {
                            Some((l.clone(), r.clone()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }),
        )
        .into_iter()
        .find(|c| c.contains(s))
        .unwrap_or_else(|| {
            let mut hs = HashSet::new();
            hs.insert(s.clone());
            hs
        })
    }

    fn isa_expr(&mut self, left: &Term, right: &Term) -> PolarResult<&mut Self> {
        match right.value() {
            Value::Pattern(Pattern::Dictionary(fields)) => {
                fields
                    .fields
                    .iter()
                    .rev()
                    .fold(Ok(self), |s, (field, value)| {
                        let this = s?;
                        // Produce a constraint like left.field = value
                        let field = right.clone_with_value(value!(field.0.as_ref()));
                        let left = left.clone_with_value(value!(op!(Dot, left.clone(), field)));
                        let op = term!(op!(Unify, left, this.deref(value)));
                        this.add_constraint(&op)
                    })
            }
            Value::Pattern(Pattern::Instance(InstanceLiteral { fields, tag })) => {
                // TODO(gj): assert that a simplified expression contains at most 1 unification
                // involving a particular variable.
                // TODO(gj): Ensure `op!(And) matches X{}` doesn't die after these changes.
                let var = left.value().as_symbol()?;
                let names = self.get_names(var);
                let run_goal = {
                    let (simplified, _) = {
                        // Get the existing partial on the LHS variable.
                        let partial = self.substitution.get_constraints(var).into();
                        simplify_partial(var, partial, names.clone(), false)
                    };
                    let simplified = simplified.value().as_expression()?;

                    // TODO (dhatch): what if there is more than one var = dot_op constraint?
                    // What if the one there is is in a not, or an or, or something
                    let lhs_of_matches = simplified
                        .constraints()
                        .into_iter()
                        .find_map(|c| match c.operator {
                            Operator::Unify
                                if &c.args[0] == left
                                    && c.args[1].value().as_expression().map(|o| o.operator)
                                        == Ok(Operator::Dot) =>
                            {
                                Some(c.args[1].clone())
                            }
                            Operator::Unify
                                if &c.args[1] == left
                                    && c.args[0].value().as_expression().map(|o| o.operator)
                                        == Ok(Operator::Dot) =>
                            {
                                Some(c.args[0].clone())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| left.clone());

                    Goal::Run(Box::new(IsaConstraintCheck::new(
                        simplified.constraints(),
                        op!(Isa, lhs_of_matches, right.clone()),
                        names,
                    )))
                };

                let constraints: Vec<_> = {
                    // Construct field-less matches operation.
                    let tag_pattern =
                        right.clone_with_value(value!(pattern!(instance!(tag.clone()))));
                    let type_constraint = op!(Isa, left.clone(), tag_pattern);
                    // Construct field constraints.
                    fields
                        .fields
                        .iter()
                        .rev()
                        .map(|(f, v)| {
                            let field = right.clone_with_value(value!(f.0.as_ref()));
                            let left = left.clone_with_value(value!(op!(Dot, left.clone(), field)));
                            op!(Unify, left, self.deref(v))
                        })
                        .into_iter()
                        .chain(std::iter::once(type_constraint))
                        .map(|op| Goal::AddConstraint(op.into()))
                        .collect()
                };

                // Run compatibility check.
                self.choose_conditional(
                    vec![run_goal],
                    constraints,
                    vec![Goal::CheckError, Goal::Backtrack],
                )
            }

            _ => self.add_constraint(&op!(Unify, left.clone(), right.clone()).into()),
        }
    }

    /// To evaluate `left matches Union`, look up `Union`'s member classes and create a choicepoint
    /// to check if `left` matches any of them.
    fn isa_union(&mut self, left: &Term, union: &Term) -> PolarResult<&mut Self> {
        let member_isas = {
            self.kb()
                .get_union_members(union)
                .iter()
                .map(|member| {
                    let tag = member.value().as_symbol().unwrap().0.as_str();
                    let pattern = member.clone_with_value(value!(pattern!(instance!(tag))));
                    vec![Goal::Isa(left.clone(), pattern)]
                })
                .collect::<Vec<_>>()
        };
        self.choose(member_isas)
    }

    pub fn lookup(
        &mut self,
        dict: &Dictionary,
        field: &Term,
        value: &Term,
    ) -> PolarResult<&mut Self> {
        let field = self.deref(field);
        match field.value() {
            Value::Variable(_) => self.choose({
                dict.fields.iter().map(|(k, v)| {
                    vec![
                        Goal::Unify(
                            field.clone_with_value(Value::String(k.clone().0)),
                            field.clone(),
                        ),
                        Goal::Unify(v.clone(), value.clone()),
                    ]
                })
            }),
            Value::String(field) => dict
                .fields
                .get(&Symbol(field.clone()))
                .map_or(Self::nope(), move |retrieved| {
                    self.goal(Goal::Unify(retrieved.clone(), value.clone()))
                }),
            v => self.type_error(
                &field,
                format!("cannot look up field {:?} on a dictionary", v),
            ),
        }
    }

    /// Return an external call event to look up a field's value
    /// in an external instance. Push a `Goal::LookupExternal` as
    /// an alternative on the last choice point to poll for results.
    pub fn lookup_external(
        &mut self,
        call_id: u64,
        instance: &Term,
        field: &Term,
    ) -> PolarResult<QueryEvent> {
        let (field_name, args, kwargs): (
            Symbol,
            Option<Vec<Term>>,
            Option<BTreeMap<Symbol, Term>>,
        ) = match self.deref(field).value() {
            Value::Call(Call { name, args, kwargs }) => (
                name.clone(),
                Some(args.iter().map(|arg| self.deref(arg)).collect()),
                kwargs.as_ref().map(|unwrapped| {
                    unwrapped
                        .iter()
                        .map(|(k, v)| (k.to_owned(), self.deref(v)))
                        .collect()
                }),
            ),
            Value::String(field) => (Symbol(field.clone()), None, None),
            v => {
                return self.type_error(
                    field,
                    format!("cannot look up field {:?} on an external instance", v),
                )
            }
        };

        // add an empty choice point; lookups return only one value
        // but we'll want to cut if we get back nothing
        self.push_choice(vec![]).log_with(
            || {
                let mut msg = format!("LOOKUP: {}.{}", instance.to_string(), field_name);
                msg.push('(');
                let args = args
                    .clone()
                    .unwrap_or_else(Vec::new)
                    .into_iter()
                    .map(|a| a.to_polar());
                let kwargs = kwargs
                    .clone()
                    .unwrap_or_else(BTreeMap::new)
                    .into_iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_polar()));
                msg.push_str(&args.chain(kwargs).collect::<Vec<String>>().join(", "));
                msg.push(')');
                msg
            },
            &[],
        );

        Ok(QueryEvent::ExternalCall {
            call_id,
            instance: self.deref(instance),
            attribute: field_name,
            args,
            kwargs,
        })
    }

    /// Query for the provided term.
    ///
    /// Uses the knowledge base to get an ordered list of rules.
    /// Creates a choice point over each rule, where each alternative
    /// consists of unifying the rule head with the arguments, then
    /// querying for each body clause.
    fn query(&mut self, term: &Term) -> PolarResult<QueryEvent> {
        // Don't log if it's just a single element AND like lots of rule bodies tend to be.
        if !matches!(&term.value().as_expression(), Ok(Operation { operator: Operator::And, args }) if args.len() == 1)
        {
            self.log_with(|| format!("QUERY: {}", term.to_polar()), &[term]);
        }

        self.queries.push(term.clone());
        self.goal(Goal::PopQuery(term.clone()))?;
        self.trace.push(Rc::new(Trace {
            node: Node::Term(term.clone()),
            children: vec![],
        }));

        match &term.value() {
            Value::Call(predicate) => self.query_for_predicate(predicate.clone()),
            Value::Expression(operation) => self.query_for_operation(operation),
            Value::Variable(sym) => self
                .goal(
                    if let Some(VariableState::Bound(val)) = self.variable_state(sym) {
                        Goal::Query(val)
                    } else {
                        Goal::Unify(term.clone(), term!(true))
                    },
                )?
                .done(),
            Value::Boolean(true) => self.done(),
            Value::Boolean(false) => self.go_back()?.done(),
            _ =>
            // everything else dies horribly and in pain
            {
                self.type_error(
                    term,
                    format!(
                        "{} isn't something that is true or false so can't be a condition",
                        term.value().to_polar()
                    ),
                )
            }
        }
    }

    /// Create a choice over the applicable rules.
    fn query_for_predicate(&mut self, predicate: Call) -> PolarResult<QueryEvent> {
        assert!(predicate.kwargs.is_none());
        let goals = match self.kb.read().unwrap().get_generic_rule(&predicate.name) {
            None => vec![Goal::Backtrack],
            Some(generic_rule) => {
                assert_eq!(generic_rule.name, predicate.name);

                let args = predicate.args.iter().map(|t| self.deref(t)).collect();
                let rules = generic_rule.get_applicable_rules(&args);

                vec![
                    Goal::TraceStackPush,
                    Goal::CallRules(rules, args),
                    Goal::TraceStackPop,
                ]
            }
        };
        self.append_goals(goals)?;
        Self::yes()
    }

    fn query_for_operation(&mut self, opn: &Operation) -> PolarResult<QueryEvent> {
        let mut args = opn.args.clone();
        let operator = opn.operator;
        match operator {
            Operator::And =>
            // Query for each conjunct.
            {
                self.goal(Goal::TraceStackPop)?
                    .append_goals(args.into_iter().map(Goal::Query))?
                    .goal(Goal::TraceStackPush)?
                    .done()
            }
            Operator::Or =>
            // Make an alternative Query for each disjunct.
            {
                self.choose(args.into_iter().map(|term| vec![Goal::Query(term)]))?
                    .done()
            }
            Operator::Not => {
                // Query in a sub-VM and invert the results.
                assert_eq!(args.len(), 1);
                let term = args.pop().unwrap();
                let add_constraints = Rc::new(RefCell::new(Bindings::new()));
                let inverter = Box::new(Inverter::new(
                    self,
                    vec![Goal::Query(term)],
                    add_constraints.clone(),
                    self.substitution.bsp(),
                ));
                self.choose_conditional(
                    vec![Goal::Run(inverter)],
                    vec![Goal::AddConstraintsBatch(add_constraints)],
                    vec![Goal::Backtrack],
                )?
                .done()
            }
            Operator::Assign => {
                assert_eq!(args.len(), 2);
                let right = args.pop().unwrap();
                let left = args.pop().unwrap();
                match (left.value(), right.value()) {
                    (Value::Variable(var), _) => match self.variable_state(var) {
                        None => self.goal(Goal::Unify(left, right))?.done(),
                        _ => self.type_error(
                            &left,
                            format!(
                                "Can only assign to unbound variables, {} is not unbound.",
                                var.to_polar()
                            ),
                        ),
                    },
                    _ => self
                        .type_error(&left, format!("Cannot assign to type {}.", left.to_polar())),
                }
            }

            Operator::Unify => {
                // Push a `Unify` goal
                assert_eq!(args.len(), 2);
                let r = args.pop().unwrap();
                let l = args.pop().unwrap();
                self.goal(Goal::Unify(l, r))?.done()
            }
            Operator::Dot => self.query_op_helper_helper(opn, Self::dot_op_helper, false, false),

            op if op.is_cmp() => {
                self.query_op_helper_helper(opn, Self::comparison_op_helper, true, true)
            }

            op if op.is_math() => {
                self.query_op_helper_helper(opn, Self::arithmetic_op_helper, true, true)
            }

            Operator::In => self.query_op_helper_helper(opn, Self::in_op_helper, false, true),

            Operator::Debug => {
                let message = self.debugger.break_msg(self).unwrap_or_else(|| {
                    format!(
                        "debug({})",
                        args.iter()
                            .map(|arg| self.deref(arg).to_polar())
                            .collect::<Vec<String>>()
                            .join(", ")
                    )
                });
                self.goal(Goal::Debug(message))?.done()
            }
            Operator::Print => {
                self.print(
                    &args
                        .iter()
                        .map(|arg| self.deref(arg).to_polar())
                        .collect::<Vec<String>>()
                        .join(", "),
                );
                self.done()
            }
            Operator::New => {
                assert_eq!(args.len(), 2);
                let result = args.pop().unwrap();
                assert!(
                    matches!(result.value(), Value::Variable(_)),
                    "Must have result variable as second arg."
                );
                let constructor = args.pop().unwrap();
                let instance_id = self.new_id();
                let instance =
                    constructor.clone_with_value(Value::ExternalInstance(ExternalInstance {
                        instance_id,
                        constructor: Some(constructor.clone()),
                        repr: Some(constructor.to_polar()),
                    }));

                // A goal is used here in case the result is already bound to some external
                // instance.
                self.append_goals(vec![
                    Goal::Unify(result, instance),
                    Goal::MakeExternal {
                        instance_id,
                        constructor,
                    },
                ])?
                .done()
            }
            Operator::Cut => {
                // Remove all choices created before this cut that are in the
                // current rule body.
                let mut choice_index = self.choices.len();
                for choice in self.choices.iter().rev() {
                    // Comparison excludes the rule body & cut operator (the last two elements of self.queries)
                    let prefix = &self.queries[..(self.queries.len() - 2)];
                    if choice.queries.starts_with(prefix) {
                        // If the choice has the same query stack as the current
                        // query stack, remove it.
                        choice_index -= 1;
                    } else {
                        break;
                    }
                }

                self.goal(Goal::Cut(choice_index))?.done()
            }
            Operator::Isa => {
                // TODO (dhatch): Use query op helper.
                assert_eq!(args.len(), 2);
                let right = args.pop().unwrap();
                let left = args.pop().unwrap();
                self.goal(Goal::Isa(left, right))?.done()
            }
            Operator::ForAll => {
                assert_eq!(args.len(), 2);
                let term = Term::from(Operation {
                    operator,
                    args: args.clone(),
                });
                let action = args.pop().unwrap();
                let condition = args.pop().unwrap();
                // For all is implemented as !(condition, !action).
                let op = Operation {
                    operator: Operator::Not,
                    args: vec![term.clone_with_value(Value::Expression(Operation {
                        operator: Operator::And,
                        args: vec![
                            condition,
                            term.clone_with_value(Value::Expression(Operation {
                                operator: Operator::Not,
                                args: vec![action],
                            })),
                        ],
                    }))],
                };
                let double_negation = term.clone_with_value(Value::Expression(op));
                self.goal(Goal::Query(double_negation))?.done()
            }
            _ => unreachable!(),
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn query_op_helper_helper<F>(
        &mut self,
        expn: &Operation,
        eval: F,
        leftp: bool,
        rightp: bool,
    ) -> PolarResult<QueryEvent>
    where
        F: Fn(&mut Self, Term) -> PolarResult<QueryEvent>,
    {
        let operator = expn.operator;
        let args = expn.args.clone();
        let term = Term::from(Operation { operator, args });
        self.query_op_helper(term, eval, leftp, rightp)
    }

    /// Handle variables & constraints as arguments to various operations.
    /// Calls the `eval` method to handle ground terms.
    ///
    /// Arguments:
    ///
    /// - handle_unbound_left_var: If set to `false`, allow `eval` to handle
    ///   operations with an unbound left variable, instead of adding a constraint.
    ///   Some operations, like `In`, emit new goals or choice points when the left
    ///   operand is a variable.
    /// - handle_unbound_right_var: Same as above but for the RHS. `Dot` uses this.
    #[allow(clippy::many_single_char_names)]
    fn query_op_helper<F>(
        &mut self,
        term: Term,
        eval: F,
        handle_unbound_left_var: bool,
        handle_unbound_right_var: bool,
    ) -> PolarResult<QueryEvent>
    where
        F: Fn(&mut Self, Term) -> PolarResult<QueryEvent>,
    {
        let Operation { operator: op, args } = term.value().as_expression().unwrap();

        let mut args = args.clone();
        assert!(args.len() >= 2);
        let (left, right) = (&args[0], &args[1]);

        match (left.value(), right.value()) {
            (Value::Expression(_), _)
            | (_, Value::Expression(_))
            | (Value::RestVariable(_), _)
            | (_, Value::RestVariable(_)) => {
                panic!("invalid query");
            }
            _ => {}
        };

        if let Value::Variable(r) = right.value() {
            if let Some(VariableState::Bound(x)) = self.variable_state(r) {
                args[1] = x;
                self.goal(Goal::Query(term.clone_with_value(Value::Expression(
                    Operation {
                        operator: *op,
                        args,
                    },
                ))))?;
                return Self::yes();
            } else if !handle_unbound_right_var && left.value().as_symbol().is_err() {
                return eval(self, term);
            }
        }

        if let Value::Variable(l) = left.value() {
            if let Some(VariableState::Bound(x)) = self.variable_state(l) {
                args[0] = x;
                self.goal(Goal::Query(term.clone_with_value(Value::Expression(
                    Operation {
                        operator: *op,
                        args,
                    },
                ))))?;
                return Self::yes();
            } else if !handle_unbound_left_var && right.value().as_symbol().is_err() {
                return eval(self, term);
            }
        }

        if left.value().as_symbol().is_ok() || right.value().as_symbol().is_ok() {
            self.add_constraint(&term)?;
            return Self::yes();
        }

        eval(self, term)
    }

    /// Evaluate comparison operations.
    fn comparison_op_helper(&mut self, term: Term) -> PolarResult<QueryEvent> {
        let Operation { operator: op, args } = term.value().as_expression().unwrap();

        assert_eq!(args.len(), 2);
        let (left, right) = (&args[0], &args[1]);

        match (left.value(), right.value()) {
            (Value::ExternalInstance(_), _) | (_, Value::ExternalInstance(_)) => {
                // Generate a symbol for the external result and bind to `false` (default).
                let (call_id, answer) = self.new_call_var("external_op_result", false.into());

                // Check that the external result is `true` when we return.
                self.goal(Goal::Unify(answer, Term::from(true)))?;

                // Emit an event for the external operation.
                Ok(QueryEvent::ExternalOp {
                    call_id,
                    operator: *op,
                    args: vec![left.clone(), right.clone()],
                })
            }
            _ => {
                if op.cmp(left.value(), right.value())? {
                    self.done()
                } else {
                    self.go_back()?.do_goals()
                }
            }
        }
    }

    // TODO(ap, dhatch): Rewrite 3-arg arithmetic ops as 2-arg + unify,
    // like we do for dots; e.g., `+(a, b, c)` → `c = +(a, b)`.
    /// Evaluate arithmetic operations.
    fn arithmetic_op_helper(&mut self, term: Term) -> PolarResult<QueryEvent> {
        let Operation { operator: op, args } = term.value.as_expression().unwrap();

        assert_eq!(args.len(), 3);
        let (left, right) = (args[0].value().clone(), args[1].value().clone());
        let result = &args[2];
        assert!(matches!(result.value(), Value::Variable(_)));
        if let Some(answer) = match op {
            Operator::Add => left + right,
            Operator::Sub => left - right,
            Operator::Mul => left * right,
            Operator::Div => left / right,
            Operator::Mod => (left).modulo(right),
            Operator::Rem => left % right,
            _ => unreachable!("didn't you check op.is_math()?"),
        } {
            self.goal(Goal::Unify(term.clone_with_value(answer), result.clone()))?
                .done()
        } else {
            self.err_ctx(
                &term,
                RuntimeError::ArithmeticError {
                    msg: term.to_polar(),
                },
            )
        }
    }

    /// Push appropriate goals for lookups on dictionaries and instances.
    fn dot_op_helper(&mut self, term: Term) -> PolarResult<QueryEvent> {
        let Operation { operator: op, args } = term.value().as_expression().unwrap();
        assert_eq!(*op, Operator::Dot, "expected a dot operation");

        let mut args = args.clone();
        assert_eq!(args.len(), 3);
        let (object, field, value) = (&args[0], &args[1], &args[2]);

        match object.value() {
            // Push a `Lookup` goal for simple field lookups on dictionaries.
            Value::Dictionary(dict)
                if matches!(field.value(), Value::String(_) | Value::Variable(_)) =>
            {
                self.goal(Goal::Lookup {
                    dict: dict.clone(),
                    field: field.clone(),
                    value: args.remove(2),
                })
            }
            // Push an `ExternalLookup` goal for external instances and built-ins.
            Value::Dictionary(_)
            | Value::ExternalInstance(_)
            | Value::List(_)
            | Value::Number(_)
            | Value::String(_) => {
                let answer = self.kb().gensym("lookup_value");
                let call_id = self.new_call_id(&answer);
                self.append_goals(vec![
                    Goal::LookupExternal {
                        call_id,
                        field: field.clone(),
                        instance: object.clone(),
                    },
                    Goal::CheckError,
                    Goal::Unify(value.clone(), Term::from(answer)),
                ])
            }
            Value::Variable(v) => {
                if matches!(field.value(), Value::Call(_)) {
                    self.err_ctx(
                        object,
                        RuntimeError::Unsupported {
                            msg: format!("cannot call method on unbound variable {}", v),
                        },
                    )
                } else {
                    // Translate `.(object, field, value)` → `value = .(object, field)`.
                    let dot2 = op!(Dot, object.clone(), field.clone());
                    let value = self.deref(value);
                    let term = Term::from(op!(Unify, value, dot2.into()));
                    self.add_constraint(&term)
                }
            }
            _ => self.type_error(
                object,
                format!(
                    "can only perform lookups on dicts and instances, this is {}",
                    object.to_polar()
                ),
            ),
        }?;
        Ok(QueryEvent::None)
    }

    fn is_ground(&self, item: &Term) -> bool {
        self.substitution.is_ground(item)
    }

    fn in_op_helper(&mut self, term: Term) -> PolarResult<QueryEvent> {
        let Operation { args, .. } = term.value().as_expression().unwrap();

        assert_eq!(args.len(), 2);
        let item = &args[0];
        let iterable = &args[1];
        let item_is_ground = self.is_ground(item);

        match iterable.value() {
            // Unify item with each element of the list, skipping non-matching ground terms.
            Value::List(terms) => self.choose(
                terms
                    .iter()
                    .filter(|term| {
                        !item_is_ground || !self.is_ground(term) || term.value() == item.value()
                    })
                    .map(|term| match term.value() {
                        Value::RestVariable(v) => {
                            let term = op!(In, item.clone(), Term::from(v.clone())).into();
                            vec![Goal::Query(term)]
                        }
                        _ => vec![Goal::Unify(item.clone(), term.clone())],
                    })
                    .collect::<Vec<Vec<Goal>>>(),
            ),
            // Unify item with each (k, v) pair of the dict, skipping non-matching ground terms.
            Value::Dictionary(dict) => self.choose(
                dict.fields
                    .iter()
                    .map(|(k, v)| {
                        iterable.clone_with_value(Value::List(vec![
                            v.clone_with_value(Value::String(k.0.clone())),
                            v.clone(),
                        ]))
                    })
                    .filter(|term| {
                        !item_is_ground || !self.is_ground(term) || term.value() == item.value()
                    })
                    .map(|term| vec![Goal::Unify(item.clone(), term)])
                    .collect::<Vec<Vec<Goal>>>(),
            ),
            // Unify item with each element of the string
            // FIXME (gw): this seems strange, wouldn't a substring search make more sense?
            Value::String(s) => self.choose(
                s.chars()
                    .map(|c| c.to_string())
                    .map(Value::String)
                    .filter(|c| !item_is_ground || c == item.value())
                    .map(|c| vec![Goal::Unify(item.clone(), iterable.clone_with_value(c))])
                    .collect::<Vec<Vec<Goal>>>(),
            ),
            // Push an `ExternalLookup` goal for external instances
            Value::ExternalInstance(_) => {
                // Generate symbol for next result and leave the variable unbound, so that unification with the result does not fail
                // Unification of the `next_sym` variable with the result of `NextExternal` happens in `fn external_call_result()`
                // `external_call_result` is the handler for results from both `LookupExternal` and `NextExternal`, so neither can bind the
                // call ID variable to `false`.
                let next_sym = self.kb().gensym("next_value");
                let call_id = self.new_call_id(&next_sym);

                // append unify goal to be evaluated after
                // next result is fetched
                self.append_goals(vec![
                    Goal::NextExternal {
                        call_id,
                        iterable: self.deref(iterable),
                    },
                    Goal::Unify(item.clone(), Term::from(next_sym)),
                ])
            }
            _ => self.type_error(
                iterable,
                format!(
                    "can only use `in` on an iterable value, this is {:?}",
                    iterable.value()
                ),
            ),
        }?;
        Self::yes()
    }

    fn maybe(&mut self, b: bool) -> PolarResult<&mut Self> {
        if b {
            Ok(self)
        } else {
            Self::nope()
        }
    }

    /// Unify `left` and `right` terms.
    ///
    /// Outcomes of a unification are:
    ///  - Successful unification => bind zero or more variables to values
    ///  - Recursive unification => more `Unify` goals are pushed onto the stack
    ///  - Failure => backtrack
    fn unify(&mut self, left: &Term, right: &Term) -> PolarResult<&mut Self> {
        match (left.value(), right.value()) {
            // Unify two variables.
            // TODO(gj): (Var, Rest) + (Rest, Var) cases might be unreachable.
            (Value::Variable(l), Value::Variable(r))
            | (Value::Variable(l), Value::RestVariable(r))
            | (Value::RestVariable(l), Value::Variable(r))
            | (Value::RestVariable(l), Value::RestVariable(r))
                if l == r =>
            {
                Ok(self)
            }

            (Value::Variable(_), _) | (Value::RestVariable(_), _) => self.bind(left, right.clone()),
            (_, Value::Variable(_)) | (_, Value::RestVariable(_)) => self.bind(right, left.clone()),

            (Value::Number(left), Value::Number(right)) => self.maybe(left == right),
            (Value::Boolean(left), Value::Boolean(right)) => self.maybe(left == right),
            (Value::String(left), Value::String(right)) => self.maybe(left == right),

            // Unify lists by recursively unifying their elements.
            (Value::List(l), Value::List(r)) => {
                self.uni_list(l, r, |(l, r)| Goal::Unify(l.clone(), r.clone()))
            }

            (Value::Expression(op), other) | (other, Value::Expression(op)) if matches!(op, Operation { operator: Operator::Dot, args } if args.len() == 2) => {
                self.goal(Goal::Query(Term::from(op!(
                    Dot,
                    op.args[0].clone(),
                    op.args[1].clone(),
                    Term::from(other.clone())
                ))))
            }
            (Value::Expression(_), _) | (_, Value::Expression(_)) => self.type_error(
                left,
                format!(
                    "cannot unify expressions directly `{}` = `{}`",
                    left.to_polar(),
                    right.to_polar()
                ),
            ),

            (Value::Pattern(_), _) | (_, Value::Pattern(_)) => self.type_error(
                left,
                format!(
                    "cannot unify patterns directly `{}` = `{}`",
                    left.to_polar(),
                    right.to_polar()
                ),
            ),

            // Unify predicates like unifying heads
            (Value::Call(left), Value::Call(right)) => {
                assert!(left.kwargs.is_none()); // Handled in the parser.
                assert!(right.kwargs.is_none());
                self.maybe(left.name == right.name && left.args.len() == right.args.len())?
                    .append_goals(
                        left.args
                            .iter()
                            .zip(right.args.iter())
                            .map(|(left, right)| Goal::Unify(left.clone(), right.clone())),
                    )
            }

            (Value::Dictionary(left), Value::Dictionary(right)) => {
                let lfs: HashSet<&Symbol> = left.fields.keys().collect();
                let rfs: HashSet<&Symbol> = right.fields.keys().collect();
                left.fields
                    .iter()
                    .fold(self.maybe(lfs == rfs), |s, (k, v)| {
                        let this = s?;
                        let right = right.fields.get(k).unwrap().clone();
                        this.goal(Goal::Unify(v.clone(), right))
                    })
            }

            (
                Value::ExternalInstance(ExternalInstance { instance_id: l, .. }),
                Value::ExternalInstance(ExternalInstance { instance_id: r, .. }),
            ) if l == r => Ok(self),

            (Value::ExternalInstance(_), _) | (_, Value::ExternalInstance(_)) => {
                self.goal(Goal::Query(Term::from(Operation {
                    operator: Operator::Eq,
                    args: vec![left.clone(), right.clone()],
                })))
            }

            // Anything else fails.
            _ => Self::nope(),
        }
    }

    /// "Unify" two lists element-wise, respecting rest-variables.
    /// Used by both `unify` and `isa`; hence the third argument,
    /// a closure that builds sub-goals.
    #[allow(clippy::ptr_arg)]
    fn uni_list<'a, F>(
        &mut self,
        left: &'a TermList,
        right: &'a TermList,
        unify: F,
    ) -> PolarResult<&mut Self>

    where
        F: FnMut((&Term, &Term)) -> Goal,
    {
        self.uni_list_(vec![], left.iter(), right.iter(), unify)
    }

    fn uni_list_<'a, F, I>(
        &mut self,
        mut goals: Vec<Goal>,
        mut l: I, 
        mut r: I, 
        mut uni: F,
    ) -> PolarResult<&mut Self> 

    where
        F: FnMut((&Term, &Term)) -> Goal,
        I: Iterator<Item = &'a Term>
    {
        let ipush = |x, i| Term::from(Value::List(std::iter::once(x).chain(i).cloned().collect()));
        let revar = |y: &Symbol| Term::from(Value::Variable(y.clone()));

        match (l.next(), r.next()) {
            (None, None) => self.append_goals(goals),
            (Some(_), None) | (None, Some(_)) => Self::nope(),
            (Some(l0), Some(r0)) => match (l0.value(), r0.value()) {
                (Value::RestVariable(_), Value::RestVariable(_)) => {
                    goals.push(uni((l0, r0)));
                    self.append_goals(goals)
                }
                (Value::RestVariable(ll), _) => {
                    goals.push(uni((&revar(ll), &ipush(r0, r))));
                    self.append_goals(goals)
                }
                (_, Value::RestVariable(rr)) => {
                    goals.push(uni((&ipush(l0, l), &revar(rr))));
                    self.append_goals(goals)
                }
                _ => {
                    goals.push(uni((l0, r0)));
                    self.uni_list_(goals, l, r, uni)
                }
            }
        }
    }


    #[allow(clippy::ptr_arg)]
    fn call_rules(&mut self, rules: &Rules, args: &TermList) -> PolarResult<&mut Self> {
        let mut alternatives = Vec::with_capacity(rules.len());
        for rule in rules.iter() {
            let mut goals = vec![
                Goal::TraceRule(Rc::new(Trace {
                    node: Node::Rule(rule.clone()),
                    children: vec![],
                })),
                Goal::TraceStackPush,
            ];
            let Rule { body, params, .. } = self.rename_rule_vars(rule);

            // Unify the arguments with the formal parameters.
            for (arg, param) in args.iter().zip(params.iter()) {
                goals.push(Goal::Unify(arg.clone(), param.parameter.clone()));
                if let Some(specializer) = &param.specializer {
                    goals.push(Goal::Isa(param.parameter.clone(), specializer.clone()));
                }
            }

            // Query for the body clauses.
            goals.push(Goal::Query(body.clone()));
            goals.push(Goal::TraceStackPop);

            alternatives.push(goals)
        }

        // Choose the first alternative, and push a choice for the rest.
        self.choose(alternatives)
    }

    /// Succeed if `left` is more specific than `right` with respect to `args`.
    #[allow(clippy::ptr_arg)]
    fn is_more_specific(
        &mut self,
        left: &Rule,
        right: &Rule,
        args: &TermList,
    ) -> PolarResult<&mut Self> {
        let zipped = left.params.iter().zip(right.params.iter()).zip(args.iter());
        for ((left, right), arg) in zipped {
            match (&left.specializer, &right.specializer) {
                // neither is more specific, continue to the next argument.
                (None, None) => continue,
                // left more specific, ok
                (Some(_), None) => return Ok(self),
                // right more specific, backtrack
                (None, Some(_)) => return Self::nope(),

                // If both specs are unions, they have the same specificity regardless of whether
                // they're the same or different unions.
                //
                // TODO(gj): when we have unions beyond `Actor` and `Resource`, we'll need to be
                // smarter about this check since UnionA is more specific than UnionB if UnionA is
                // a member of UnionB.
                (Some(left), Some(right)) => {
                    let (l, r) = (self.kb().is_union(left), self.kb().is_union(right));
                    match (l, r) {
                        (true, true) => continue,
                        (true, false) => return Self::nope(),
                        (false, true) => return Ok(self),
                        (false, false) if left == right => continue,
                        _ => {
                            // If you find two non-equal specializers, that comparison determines the relative
                            // specificity of the two rules completely. As soon as you have two specializers
                            // that aren't the same and you can compare them and ask which one is more specific
                            // to the relevant argument, you're done.
                            let answer = self.kb().gensym("is_subspecializer");
                            // Bind answer to false as a starting point in case is subspecializer doesn't
                            // bind any result.
                            // This is done here for safety to avoid a bug where `answer` is unbound by
                            // `IsSubspecializer` and the `Unify` Goal just assigns it to `true` instead
                            // of checking that is is equal to `true`.
                            self.bind(&Term::from(answer.clone()), false.into())?;

                            return self.append_goals(vec![
                                Goal::IsSubspecializer {
                                    answer: answer.clone(),
                                    left: left.clone(),
                                    right: right.clone(),
                                    arg: arg.clone(),
                                },
                                Goal::Unify(Term::from(answer), true.into()),
                            ]);
                        }
                    }
                }
            }
        }
        Self::nope()
    }

    /// Determine if `left` is a more specific specializer ("subspecializer") than `right`
    fn is_subspecializer(
        &mut self,
        answer: &Symbol,
        left: &Term,
        right: &Term,
        arg: &Term,
    ) -> PolarResult<QueryEvent> {
        let arg = self.deref(arg);
        match (arg.value(), left.value(), right.value()) {
            (
                Value::ExternalInstance(instance),
                Value::Pattern(Pattern::Instance(left_lit)),
                Value::Pattern(Pattern::Instance(right_lit)),
            ) => {
                let call_id = self.new_call_id(answer);
                let instance_id = instance.instance_id;
                if left_lit.tag == right_lit.tag
                    && !(left_lit.fields.fields.is_empty() && right_lit.fields.fields.is_empty())
                {
                    self.goal(Goal::IsSubspecializer {
                        answer: answer.clone(),
                        left: left.clone_with_value(Value::Pattern(Pattern::Dictionary(
                            left_lit.fields.clone(),
                        ))),
                        right: right.clone_with_value(Value::Pattern(Pattern::Dictionary(
                            right_lit.fields.clone(),
                        ))),
                        arg,
                    })?;
                }
                // check ordering based on the classes
                Ok(QueryEvent::ExternalIsSubSpecializer {
                    call_id,
                    instance_id,
                    left_class_tag: left_lit.tag.clone(),
                    right_class_tag: right_lit.tag.clone(),
                })
            }
            (
                _,
                Value::Pattern(Pattern::Dictionary(left)),
                Value::Pattern(Pattern::Dictionary(right)),
            ) => {
                let left_fields: HashSet<&Symbol> = left.fields.keys().collect();
                let right_fields: HashSet<&Symbol> = right.fields.keys().collect();

                // The dictionary with more fields is taken as more specific.
                // The assumption here is that rules have already been filtered
                // for applicability.
                if left_fields.len() != right_fields.len() {
                    self.rebind_external_answer(
                        answer,
                        Term::from(right_fields.len() < left.fields.len()),
                    );
                }
                self.done()
            }
            (_, Value::Pattern(Pattern::Instance(_)), Value::Pattern(Pattern::Dictionary(_))) => {
                self.rebind_external_answer(answer, Term::from(true)).done()
            }
            _ => self
                .rebind_external_answer(answer, Term::from(false))
                .done(),
        }
    }

    pub fn term_source(&self, term: &Term, include_info: bool) -> String {
        let source = self.source(term);
        let span = term.span();

        let mut source_string = match (&source, &span) {
            (Some(source), Some((left, right))) => {
                source.src.chars().take(*right).skip(*left).collect()
            }
            _ => term.to_polar(),
        };

        if include_info {
            if let Some(source) = source {
                let (row, column) = loc_to_pos(&source.src, term.offset());
                source_string.push_str(&format!(" at line {}, column {}", row + 1, column));
                if let Some(filename) = source.filename {
                    source_string.push_str(&format!(" in file {}", filename));
                }
            }
        }

        source_string
    }

    fn err_ctx<A>(&self, term: &Term, error: impl Into<PolarError>) -> PolarResult<A> {
        self.err(self.kb().set_error_context(term, error))
    }

    fn type_error<A>(&self, term: &Term, msg: String) -> PolarResult<A> {
        let error = RuntimeError::TypeError {
            msg,
            stack_trace: Some(self.stack_trace()),
        };
        self.err_ctx(term, error)
    }

    fn err<A, B>(&self, err: B) -> PolarResult<A>
    where
        B: Into<PolarError>,
    {
        Err(err.into())
    }

    /// Handle an error coming from outside the vm.
    pub fn set_external_error(&mut self, message: String) {
        self.external_error = Some(message);
    }

    fn event(&self, ev: QueryEvent) -> PolarResult<QueryEvent> {
        Ok(ev)
    }

    fn done(&self) -> PolarResult<QueryEvent> {
        Self::yes()
    }
    fn yes() -> PolarResult<QueryEvent> {
        Ok(QueryEvent::None)
    }
    fn nope<A>() -> PolarResult<A> {
        Err(PolarError {
            kind: ErrorKind::Control,
            context: None,
        })
    }
}

impl Runnable for PolarVirtualMachine {
    /// Run the virtual machine. While there are goals on the stack,
    /// pop them off and execute them one at a time until we have a
    /// `QueryEvent` to return. May be called multiple times to restart
    /// the machine.
    fn run(&mut self, _: Option<&mut Counter>) -> PolarResult<QueryEvent> {
        self.start_query()
    }

    /// Handle response to a predicate posed to the application, e.g., `ExternalIsa`.
    fn external_question_result(&mut self, call_id: u64, answer: bool) -> PolarResult<()> {
        let var = self.calls.remove(&call_id).expect("bad call id");
        self.rebind_external_answer(&var, Term::from(answer));
        Ok(())
    }

    /// Handle an external result provided by the application.
    ///
    /// If the value is `Some(_)` then we have a result, and unify the
    /// symbol associated with the call ID to the result value. If the
    /// value is `None` then the external has no (more) results, so we
    /// backtrack to the choice point left by `Goal::LookupExternal`.
    fn external_call_result(&mut self, call_id: u64, term: Option<Term>) -> PolarResult<()> {
        if let Some(value) = term {
            self.log_with(|| format!("=> {}", value.to_string()), &[]);
            let sym = self.calls.get(&call_id).unwrap().to_owned();
            self.goal(Goal::Unify(Term::from(sym), value))?;
        } else {
            self.polar_log("=> No more results.", &[]);
            self.calls.remove(&call_id).expect("bad call ID");
            self.append_goals(vec![
                self.goals.last().map_or(Goal::Noop, |_| Goal::CheckError),
                Goal::Cut(self.choices.len() - 1),
                Goal::Backtrack,
            ])?;
        }
        Ok(())
    }

    /// Drive debugger.
    fn debug_command(&mut self, command: &str) -> PolarResult<()> {
        let mut debugger = self.debugger.clone();
        let maybe_goal = debugger.debug_command(command, self);
        if let Some(goal) = maybe_goal {
            self.goal(goal)?;
        }
        self.debugger = debugger;
        Ok(())
    }

    fn clone_runnable(&self) -> Box<dyn Runnable> {
        Box::new(self.clone())
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(a: &str);
}

#[cfg(test)]
mod tests {
    impl PolarVirtualMachine {
        /// Return true if there is nothing left to do.
        fn is_halted(&self) -> bool {
            self.goals.is_empty() && self.choices.is_empty()
        }

        fn set_stack_limit(&mut self, limit: usize) {
            self.stack_limit = limit;
        }

        fn new_test(kb: Arc<RwLock<KnowledgeBase>>, tracing: bool, goals: Vec<Goal>) -> Self {
            PolarVirtualMachine {
                kb,
                tracing,
                goals: GoalStack::new_reversed(goals),
                ..Default::default()
            }
        }
    }

    use permute::permute;

    use super::*;
    use crate::rewrites::unwrap_and;

    /// Shorthand for constructing Goal::Query.
    ///
    /// A one argument invocation assumes the 1st argument is the same
    /// parameters that can be passed to the term! macro.  In this invocation,
    /// typically the form `query!(op!(And, term!(TERM)))` will be used. The
    /// one argument form allows for queries with a top level operator other
    /// than AND.
    ///
    /// Multiple arguments `query!(f1, f2, f3)` result in a query with a root
    /// AND operator term.
    macro_rules! query {
        ($term:expr) => {
            Goal::Query(term!($term))
        };
        ($($term:expr),+) => {
            Goal::Query(term!(op!(And, $($term),+)))
        };
    }

    /// Macro takes two arguments, the vm and a list-like structure of
    /// QueryEvents to expect.  It will call run() for each event in the second
    /// argument and pattern match to check that the event matches what is
    /// expected.  Then `vm.is_halted()` is checked.
    ///
    /// The QueryEvent list elements can either be:
    ///   - QueryEvent::Result{EXPR} where EXPR is a HashMap<Symbol, Term>.
    ///     This is shorthand for QueryEvent::Result{bindings} if bindings == EXPR.
    ///     Use btreemap! for EXPR from the maplit package to write inline hashmaps
    ///     to assert on.
    ///   - A pattern with optional guard accepted by matches!. (QueryEvent::Result
    ///     cannot be matched on due to the above rule.)
    macro_rules! assert_query_events {
        ($vm:ident, []) => {
            assert!($vm.is_halted());
        };
        ($vm:ident, [QueryEvent::Result{$result:expr}]) => {
            assert!(matches!($vm.run(None).unwrap(), QueryEvent::Result{bindings, ..} if bindings == $result));
            assert_query_events!($vm, []);
        };
        ($vm:ident, [QueryEvent::Result{$result:expr}, $($tail:tt)*]) => {
            assert!(matches!($vm.run(None).unwrap(), QueryEvent::Result{bindings, ..} if bindings == $result));
            assert_query_events!($vm, [$($tail)*]);
        };
        ($vm:ident, [$( $pattern:pat )|+ $( if $guard: expr )?]) => {
            assert!(matches!($vm.run(None).unwrap(), $($pattern)|+ $(if $guard)?));
            assert_query_events!($vm, []);
        };
        ($vm:ident, [$( $pattern:pat )|+ $( if $guard: expr )?, $($tail:tt)*]) => {
            assert!(matches!($vm.run(None).unwrap(), $($pattern)|+ $(if $guard)?));
            assert_query_events!($vm, [$($tail)*]);
        };
        // TODO (dhatch) Be able to use btreemap! to match on specific bindings.
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn and_expression() {
        let f1 = rule!("f", [1]);
        let f2 = rule!("f", [2]);

        let rule = GenericRule::new(sym!("f"), vec![Arc::new(f1), Arc::new(f2)]);

        let mut kb = KnowledgeBase::new();
        kb.add_generic_rule(rule);

        let goal = query!(op!(And));

        let mut vm = PolarVirtualMachine::new_test(Arc::new(RwLock::new(kb)), false, vec![goal]);
        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!()},
            QueryEvent::Done(true)
        ]);

        assert!(vm.is_halted());

        let f1 = term!(call!("f", [1]));
        let f2 = term!(call!("f", [2]));
        let f3 = term!(call!("f", [3]));

        // Querying for f(1)
        vm.goal(query!(op!(And, f1.clone()))).unwrap();

        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!{}},
            QueryEvent::Done(true)
        ]);

        // Querying for f(1), f(2)
        vm.goal(query!(f1.clone(), f2.clone())).unwrap();
        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!{}},
            QueryEvent::Done(true)
        ]);

        // Querying for f(3)
        vm.goal(query!(op!(And, f3.clone()))).unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);

        // Querying for f(1), f(2), f(3)
        let parts = vec![f1, f2, f3];
        for permutation in permute(parts) {
            vm.goal(Goal::Query(Term::new_from_test(Value::Expression(
                Operation {
                    operator: Operator::And,
                    args: permutation,
                },
            ))))
            .unwrap();
            assert_query_events!(vm, [QueryEvent::Done(true)]);
        }
    }

    #[test]
    fn unify_expression() {
        let mut vm = PolarVirtualMachine::default();
        vm.goal(query!(op!(Unify, term!(1), term!(1)))).unwrap();

        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!{}},
            QueryEvent::Done(true)
        ]);

        let q = op!(Unify, term!(1), term!(2));
        vm.goal(query!(q)).unwrap();

        assert_query_events!(vm, [QueryEvent::Done(true)]);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn isa_on_lists() {
        let mut vm = PolarVirtualMachine::default();
        let one = term!(1);
        let one_list = term!([1]);
        let one_two_list = term!([1, 2]);
        let two_one_list = term!([2, 1]);
        let empty_list = term!([]);

        // [] isa []
        vm.goal(Goal::Isa(empty_list.clone(), empty_list.clone()))
            .unwrap();
        assert!(
            matches!(vm.run(None).unwrap(), QueryEvent::Result{bindings, ..} if bindings.is_empty())
        );
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1,2] isa [1,2]
        vm.goal(Goal::Isa(one_two_list.clone(), one_two_list.clone()))
            .unwrap();
        assert!(
            matches!(vm.run(None).unwrap(), QueryEvent::Result{bindings, ..} if bindings.is_empty())
        );
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1,2] isNOTa [2,1]
        vm.goal(Goal::Isa(one_two_list.clone(), two_one_list))
            .unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1] isNOTa [1,2]
        vm.goal(Goal::Isa(one_list.clone(), one_two_list.clone()))
            .unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1,2] isNOTa [1]
        vm.goal(Goal::Isa(one_two_list.clone(), one_list.clone()))
            .unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1] isNOTa []
        vm.goal(Goal::Isa(one_list.clone(), empty_list.clone()))
            .unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [] isNOTa [1]
        vm.goal(Goal::Isa(empty_list, one_list.clone())).unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1] isNOTa 1
        vm.goal(Goal::Isa(one_list.clone(), one.clone())).unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // 1 isNOTa [1]
        vm.goal(Goal::Isa(one, one_list)).unwrap();
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Done(true)
        ));
        assert!(vm.is_halted());

        // [1,2] isa [1, *rest]
        vm.goal(Goal::Isa(
            one_two_list,
            term!([1, Value::RestVariable(sym!("rest"))]),
        ))
        .unwrap();
        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!{sym!("rest") => term!([2])}},
            QueryEvent::Done(true)
        ]);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn isa_on_dicts() {
        let mut vm = PolarVirtualMachine::default();
        let dict = term!(btreemap! {
            sym!("x") => term!(1),
            sym!("y") => term!(2),
        });
        let dict_pattern = term!(pattern!(btreemap! {
            sym!("x") => term!(1),
            sym!("y") => term!(2),
        }));
        vm.goal(Goal::Isa(dict.clone(), dict_pattern.clone()))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!() }, QueryEvent::Done(true)]);

        // Dicts with identical keys and different values DO NOT isa.
        let different_dict_pattern = term!(pattern!(btreemap! {
            sym!("x") => term!(2),
            sym!("y") => term!(1),
        }));
        vm.goal(Goal::Isa(dict.clone(), different_dict_pattern))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);

        let empty_dict = term!(btreemap! {});
        let empty_dict_pattern = term!(pattern!(btreemap! {}));
        // {} isa {}.
        vm.goal(Goal::Isa(empty_dict.clone(), empty_dict_pattern.clone()))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!() }, QueryEvent::Done(true)]);

        // Non-empty dicts should isa against an empty dict.
        vm.goal(Goal::Isa(dict.clone(), empty_dict_pattern))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!() }, QueryEvent::Done(true)]);

        // Empty dicts should NOT isa against a non-empty dict.
        vm.goal(Goal::Isa(empty_dict, dict_pattern.clone()))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);

        let subset_dict_pattern = term!(pattern!(btreemap! {sym!("x") => term!(1)}));
        // Superset dict isa subset dict.
        vm.goal(Goal::Isa(dict, subset_dict_pattern)).unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!() }, QueryEvent::Done(true)]);

        // Subset dict isNOTa superset dict.
        let subset_dict = term!(btreemap! {sym!("x") => term!(1)});
        vm.goal(Goal::Isa(subset_dict, dict_pattern)).unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);
    }

    #[test]
    fn unify_dicts() {
        let mut vm = PolarVirtualMachine::default();
        // Dicts with identical keys and values unify.
        let left = term!(btreemap! {
            sym!("x") => term!(1),
            sym!("y") => term!(2),
        });
        let right = term!(btreemap! {
            sym!("x") => term!(1),
            sym!("y") => term!(2),
        });
        vm.goal(Goal::Unify(left.clone(), right)).unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!() }, QueryEvent::Done(true)]);

        // Dicts with identical keys and different values DO NOT unify.
        let right = term!(btreemap! {
            sym!("x") => term!(2),
            sym!("y") => term!(1),
        });
        vm.goal(Goal::Unify(left.clone(), right)).unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);

        // Empty dicts unify.
        vm.goal(Goal::Unify(term!(btreemap! {}), term!(btreemap! {})))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!() }, QueryEvent::Done(true)]);

        // Empty dict should not unify against a non-empty dict.
        vm.goal(Goal::Unify(left.clone(), term!(btreemap! {})))
            .unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);

        // Subset match should fail.
        let right = term!(btreemap! {
            sym!("x") => term!(1),
        });
        vm.goal(Goal::Unify(left, right)).unwrap();
        assert_query_events!(vm, [QueryEvent::Done(true)]);
    }

    #[test]
    fn unify_nested_dicts() {
        let mut vm = PolarVirtualMachine::default();

        let left = term!(btreemap! {
            sym!("x") => term!(btreemap!{
                sym!("y") => term!(1)
            })
        });
        let right = term!(btreemap! {
            sym!("x") => term!(btreemap!{
                sym!("y") => term!(sym!("result"))
            })
        });
        vm.goal(Goal::Unify(left, right)).unwrap();
        assert_query_events!(vm, [QueryEvent::Result { hashmap!{sym!("result") => term!(1)} }, QueryEvent::Done(true)]);
    }

    #[test]
    fn lookup() {
        let mut vm = PolarVirtualMachine::default();

        let fields = btreemap! {
            sym!("x") => term!(1),
        };
        let dict = Dictionary { fields };
        vm.goal(Goal::Lookup {
            dict: dict.clone(),
            field: term!(string!("x")),
            value: term!(1),
        })
        .unwrap();

        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!{}}
        ]);

        // Lookup with incorrect value
        vm.goal(Goal::Lookup {
            dict: dict.clone(),
            field: term!(string!("x")),
            value: term!(2),
        })
        .unwrap();

        assert_query_events!(vm, [QueryEvent::Done(true)]);

        // Lookup with unbound value
        vm.goal(Goal::Lookup {
            dict,
            field: term!(string!("x")),
            value: term!(sym!("y")),
        })
        .unwrap();
        assert_query_events!(vm, [
            QueryEvent::Result{hashmap!{sym!("y") => term!(1)}}
        ]);
    }

    #[test]
    fn debug() {
        let mut vm = PolarVirtualMachine::new_test(
            Arc::new(RwLock::new(KnowledgeBase::new())),
            false,
            vec![Goal::Debug("Hello".to_string())],
        );
        assert!(matches!(
            vm.run(None).unwrap(),
            QueryEvent::Debug(message) if &message[..] == "Hello"
        ));
    }

    #[test]
    fn halt() {
        let mut vm = PolarVirtualMachine::new_test(
            Arc::new(RwLock::new(KnowledgeBase::new())),
            false,
            vec![Goal::Halt],
        );
        let _ = vm.run(None).unwrap();
        assert_eq!(vm.goals.len(), 0);
        assert_eq!(vm.bindings(true).len(), 0);
    }

    #[test]
    fn unify() {
        let x = sym!("x");
        let y = sym!("y");
        let vars = term!([x.clone(), y.clone()]);
        let zero = value!(0);
        let one = value!(1);
        let vals = term!([zero.clone(), one.clone()]);
        let mut vm = PolarVirtualMachine::new_test(
            Arc::new(RwLock::new(KnowledgeBase::new())),
            false,
            vec![Goal::Unify(vars, vals)],
        );
        let _ = vm.run(None).unwrap();
        assert_eq!(
            vm.variable_state(&x),
            Some(VariableState::Bound(term!(zero)))
        );
        assert_eq!(
            vm.variable_state(&y),
            Some(VariableState::Bound(term!(one)))
        );
    }

    #[test]
    fn unify_var() {
        let x = var!("x");
        let y = var!("y");
        let z = var!("z");
        let one = term!(1);
        let two = term!(2);

        let mut vm = PolarVirtualMachine::default();

        // Left variable bound to bound right variable.
        vm.bind(&y, one.clone()).unwrap();
        vm.append_goals(vec![Goal::Unify(term!(x.clone()), term!(y))])
            .unwrap();
        let _ = vm.run(None).unwrap();
        assert_eq!(vm.deref(&x), one);
        vm.go_back().unwrap();

        // Left variable bound to value.
        vm.bind(&z, one.clone()).unwrap();
        vm.append_goals(vec![Goal::Unify(term!(z.clone()), one.clone())])
            .unwrap();
        let _ = vm.run(None).unwrap();
        assert_eq!(vm.deref(&z), one);

        // Left variable bound to value, unify with something else, backtrack.
        vm.append_goals(vec![Goal::Unify(z.clone(), two)]).unwrap();
        let _ = vm.run(None).unwrap();
        assert_eq!(vm.deref(&z), one);
    }

    #[test]
    fn test_gen_var() {
        let vm = PolarVirtualMachine::default();

        let rule = Rule {
            name: Symbol::new("foo"),
            params: vec![],
            body: Term::new_from_test(Value::Expression(Operation {
                operator: Operator::And,
                args: vec![
                    term!(1),
                    Term::new_from_test(Value::Variable(Symbol("x".to_string()))),
                    Term::new_from_test(Value::Variable(Symbol("x".to_string()))),
                    Term::new_from_test(Value::List(vec![Term::new_from_test(Value::Variable(
                        Symbol("y".to_string()),
                    ))])),
                ],
            })),
            source_info: SourceInfo::Test,
        };

        let renamed_rule = vm.rename_rule_vars(&rule);
        let renamed_terms = unwrap_and(&renamed_rule.body);
        assert_eq!(renamed_terms[1].value(), renamed_terms[2].value());
        let x_value = match &renamed_terms[1].value() {
            Value::Variable(sym) => Some(sym.0.clone()),
            _ => None,
        };
        assert_eq!(x_value.unwrap(), "_x_1");

        let y_value = match &renamed_terms[3].value() {
            Value::List(terms) => match &terms[0].value() {
                Value::Variable(sym) => Some(sym.0.clone()),
                _ => None,
            },
            _ => None,
        };
        assert_eq!(y_value.unwrap(), "_y_2");
    }

    #[test]
    fn test_is_subspecializer() {
        let mut vm = PolarVirtualMachine::default();

        // Test `is_subspecializer` case where:
        // - arg: `ExternalInstance`
        // - left: `InstanceLiteral`
        // - right: `Dictionary`
        let arg = term!(Value::ExternalInstance(ExternalInstance {
            instance_id: 1,
            constructor: None,
            repr: None,
        }));
        let left = term!(value!(Pattern::Instance(InstanceLiteral {
            tag: sym!("Any"),
            fields: Dictionary {
                fields: btreemap! {}
            }
        })));
        let right = term!(Value::Pattern(Pattern::Dictionary(Dictionary {
            fields: btreemap! {sym!("a") => term!("a")},
        })));

        let answer = vm.kb().gensym("is_subspecializer");

        match vm.is_subspecializer(&answer, &left, &right, &arg).unwrap() {
            QueryEvent::None => (),
            event => panic!("Expected None, got {:?}", event),
        }

        assert_eq!(
            vm.deref(&term!(Value::Variable(answer))),
            term!(value!(true))
        );
    }

    /* FIXME
    #[test]
    fn test_timeout() {
        let vm = PolarVirtualMachine::default();
        assert!(vm.query_timeout_ms == DEFAULT_TIMEOUT_MS);

        std::env::set_var("POLAR_TIMEOUT_MS", "0");
        let vm = PolarVirtualMachine::default();
        std::env::remove_var("POLAR_TIMEOUT_MS");
        assert!(vm.query_timeout_ms == 0);

        std::env::set_var("POLAR_TIMEOUT_MS", "500");
        let mut vm = PolarVirtualMachine::default();
        std::env::remove_var("POLAR_TIMEOUT_MS");
        // Turn this off so we don't hit it.
        vm.set_stack_limit(std::usize::MAX);

        loop {
            vm.goal(Goal::Noop).unwrap();
            vm.goal(Goal::MakeExternal {
                constructor: Term::from(true),
                instance_id: 1,
            })
            .unwrap();
            let result = vm.run(None);
            match result {
                Ok(event) => assert!(matches!(event, QueryEvent::MakeExternal { .. })),
                Err(err) => {
                    assert!(matches!(
                        err,
                        PolarError {
                            kind: ErrorKind::Runtime(
                                RuntimeError::QueryTimeout { .. }
                            ),
                            ..
                        }
                    ));

                    // End test.
                    break;
                }
            }
        }
    }
    */

    #[test]
    fn choose_conditional() {
        let mut vm = PolarVirtualMachine::new_test(
            Arc::new(RwLock::new(KnowledgeBase::new())),
            false,
            vec![],
        );
        let consequent = Goal::Debug("consequent".to_string());
        let alternative = Goal::Debug("alternative".to_string());

        // Check consequent path when conditional succeeds.
        vm.choose_conditional(
            vec![Goal::Noop],
            vec![consequent.clone()],
            vec![alternative.clone()],
        )
        .unwrap();
        assert_query_events!(vm, [
            QueryEvent::Debug(message) if &message[..] == "consequent" && vm.is_halted(),
            QueryEvent::Done(true)
        ]);

        // Check alternative path when conditional fails.
        vm.choose_conditional(
            vec![Goal::Backtrack],
            vec![consequent.clone()],
            vec![alternative.clone()],
        )
        .unwrap();
        assert_query_events!(vm, [
            QueryEvent::Debug(message) if &message[..] == "alternative" && vm.is_halted(),
            QueryEvent::Done(true)
        ]);

        // Ensure bindings are cleaned up after conditional.
        vm.choose_conditional(
            vec![
                Goal::Unify(term!(sym!("x")), term!(true)),
                query!(sym!("x")),
            ],
            vec![consequent],
            vec![alternative],
        )
        .unwrap();
        assert_query_events!(vm, [
            QueryEvent::Debug(message) if &message[..] == "consequent" && vm.bindings(true).is_empty() && vm.is_halted(),
            QueryEvent::Done(true)
        ]);
    }
}
