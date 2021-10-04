/// Manage binding state in the VM.
///
/// Bindings associate variables in the VM with constraints or values.
use std::collections::{HashMap, HashSet};

use crate::error::*;
use crate::folder::{fold_list, fold_term, Folder};
use crate::terms::{has_rest_var, Operation, Operator, Symbol, Term, Value};
use crate::vm::Goal;

#[derive(Clone, Debug)]
pub struct Binding(pub Symbol, pub Term);

// TODO This is only public for debugger and inverter.
// Eventually this should be an internal interface.
pub type BindingStack = Vec<Binding>;
pub type Bindings = HashMap<Symbol, Term>;

pub type Bsp = Bsps;
pub type FollowerId = usize;

/// Bsps represents bsps of a binding manager and its followers as a tree.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bsps {
    /// Index into `bindings` array
    bindings_index: usize,
    /// Store bsps of followers (and their followers) by follower id.
    followers: HashMap<FollowerId, Bsps>,
}

/// Variable binding state.
///
/// A variable is Unbound if it is not bound to a concrete value.
/// A variable is Bound if it is bound to a ground value (not another variable).
/// A variable is Partial if it is bound to other variables, or constrained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariableState {
    Bound(Term),
    Partial,
}

struct Derefer<'a> {
    binding_manager: &'a BindingManager,
    seen: HashSet<u64>,
}

impl<'a> Derefer<'a> {
    fn new(binding_manager: &'a BindingManager) -> Self {
        Self {
            binding_manager,
            seen: HashSet::new(),
        }
    }
}

impl<'a> Folder for Derefer<'a> {
    fn fold_list(&mut self, list: Vec<Term>) -> Vec<Term> {
        let has_rest = has_rest_var(&list);
        let mut list = fold_list(list, self);
        if has_rest {
            let last = list.pop().unwrap();
            if let Value::List(rest) = last.value() {
                list.append(&mut rest.clone());
            } else {
                list.push(last);
            }
        }
        list
    }

    fn fold_term(&mut self, t: Term) -> Term {
        match t.value() {
            Value::Expression(_) => t,
            Value::Variable(v) | Value::RestVariable(v) => {
                let hash = t.hash_value();
                if self.seen.contains(&hash) {
                    t
                } else {
                    self.seen.insert(hash);
                    let t = self.binding_manager.lookup(v).unwrap_or(t);
                    let t = fold_term(t, self);
                    self.seen.remove(&hash);
                    t
                }
            }
            _ => fold_term(t, self),
        }
    }
}

/// Represent each binding in a cycle as a unification constraint.
// TODO(gj): put this in an impl block on VariableState?
fn cycle_constraints(cycle: Vec<Symbol>) -> Operation {
    let mut constraints = op!(And);
    for (x, y) in cycle.iter().zip(cycle.iter().skip(1)) {
        constraints.add_constraint(op!(
            Unify,
            Term::from(Value::Variable(x.clone())),
            term!(y.clone())
        ));
    }
    constraints
}

impl From<Lookup<'_>> for VariableState {
    fn from(other: Lookup<'_>) -> Self {
        match other {
            Lookup::Bound(b) => VariableState::Bound(b.clone()),
            _ => VariableState::Partial,
        }
    }
}

/// Internal variable binding state.
///
/// Includes the Cycle representation in addition to VariableState.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Bound(&'a Term),
    Partial(&'a Operation),
    Cycle(Vec<Symbol>),
}

/// The `BindingManager` maintains associations between variables and values,
/// and constraints.
///
/// A variable may be:
/// - unbound
/// - bound
/// - constrained
///
/// Variables may also be bound together such that their values or constraints
/// will be the same.
///
/// A binding is created with the `bind` method.
///
/// The constraints or value associated with a variable is retrieved with `variable_state`.
#[derive(Clone, Debug, Default)]
pub struct BindingManager {
    bindings: BindingStack,
    followers: HashMap<FollowerId, BindingManager>,
    next_follower_id: FollowerId,
}

// Public interface.
impl BindingManager {
    pub fn ground<'a>(&'a self, v: &'a Term) -> Option<&'a Term> {
        match self.get(v) {
            Some(Lookup::Bound(t)) => Some(t),
            _ => None,
        }
    }

    pub fn is_ground(&self, v: &Term) -> bool {
        self.ground(v).is_some()
    }

    /// Bind `var` to `val` in the expression `partial`.
    ///
    /// If the binding succeeds, the new expression is returned as a goal. Otherwise,
    /// an error is returned.
    fn addl_binding(&mut self, partial: Operation, var: &Symbol, val: Term) -> PolarResult<Goal> {
        self.add_binding(var, val);
        Ok(Goal::Query(Term::from(partial)))
    }

    fn coconstrain(&mut self, a: &Term, b: &Term) -> PolarResult<()> {
        self.add_constraint(&Term::from(op!(Unify, a.clone(), b.clone())))
    }

    pub fn bind(&mut self, lhs: &Term, val: Term) -> PolarResult<Option<Goal>> {
        fn as_sym(t: &Term) -> &Symbol {
            t.value().as_symbol().unwrap()
        }
        let mut goals: Vec<Goal> = vec![];
        let rhs = self.get(&val);

        match (self.get(lhs), rhs) {
            // left free, right free
            (None, None) => {
                let (lhs, rhs) = (as_sym(lhs), val.clone());
                self.add_binding(lhs, rhs)
            }

            // left bound, right bound
            (Some(Lookup::Bound(a)), Some(Lookup::Bound(b))) => {
                if a == b {
                } else {
                    return Err(PolarError {
                        kind: ErrorKind::Control,
                        context: None,
                    });
                }
            }

            // left free, right bound
            (None, Some(Lookup::Bound(val))) => {
                // one side bound, other side free
                let (lhs, rhs) = (as_sym(lhs), val.clone());
                self.add_binding(lhs, rhs)
            }
            // right free, left bound
            (Some(Lookup::Bound(to)), None) => {
                let (lhs, rhs) = (as_sym(&val), to.clone());
                self.add_binding(lhs, rhs)
            }

            // left constrained, right bound
            (Some(Lookup::Partial(p)), Some(Lookup::Bound(b))) => {
                let (p, b) = (p.clone(), b.clone());
                goals.push(self.addl_binding(p, as_sym(lhs), b)?)
            }
            (Some(Lookup::Cycle(p)), Some(Lookup::Bound(b))) => {
                let (p, b) = (cycle_constraints(p), b.clone());
                goals.push(self.addl_binding(p, as_sym(lhs), b)?)
            }

            // right constrained, left bound
            (Some(Lookup::Bound(b)), Some(Lookup::Partial(p))) => {
                let (p, rhs, b) = (p.clone(), as_sym(&val), b.clone());
                goals.push(self.addl_binding(p, rhs, b)?)
            }
            (Some(Lookup::Bound(b)), Some(Lookup::Cycle(p))) => {
                let (p, rhs, b) = (cycle_constraints(p), as_sym(&val), b.clone());
                goals.push(self.addl_binding(p, rhs, b)?)
            }

            // at least one side is constrained, and RHS is definitely a symbol
            _ => self.coconstrain(lhs, &val).map(|_| ())?,
        };

        self.do_followers(|_, follower| follower.bind(lhs, val.clone()).map(|_| ()))?;

        Ok(goals.pop())
    }

    /// Add a constraint. Constraints are represented as term expressions.
    ///
    /// `term` must be an expression`.
    ///
    /// An error is returned if the constraint is incompatible with existing constraints.
    pub fn add_constraint(&mut self, term: &Term) -> PolarResult<()> {
        self.do_followers(|_, follower| follower.add_constraint(term))?;

        assert!(term.value().as_expression().is_ok());
        let mut op = op!(And, term.clone());

        // include all constraints applying to any of its variables.
        for var in op.variables().iter().rev() {
            match self.get(&Term::from(var.clone())) {
                Some(Lookup::Cycle(c)) => op = cycle_constraints(c).merge_constraints(op),
                Some(Lookup::Partial(e)) => op = e.clone().merge_constraints(op),
                _ => {}
            }
        }

        let vars = op.variables();
        let mut varset = vars.iter().collect::<HashSet<_>>();

        // replace any bound variables with their values.
        for var in vars.iter() {
            if let Some(Lookup::Bound(val)) = self.get(&Term::from(var.clone())) {
                varset.remove(var);
                match op.ground(var, val.clone()) {
                    Some(o) => op = o,
                    None => {
                        return Err(
                            RuntimeError::IncompatibleBindings("Grounding failed B".into()).into(),
                        )
                    }
                }
            }
        }

        // apply the new constraint to every remaining variable.
        for var in varset {
            self.add_binding(var, op.clone().into())
        }
        Ok(())
    }

    /// Reset the state of `BindingManager` to what it was at `to`.
    pub fn backtrack(&mut self, to: &Bsp) {
        self.do_followers(|follower_id, follower| {
            if let Some(follower_to) = to.followers.get(&follower_id) {
                follower.backtrack(follower_to);
            } else {
                follower.backtrack(&Bsp::default());
            }
            Ok(())
        })
        .unwrap();

        self.bindings.truncate(to.bindings_index)
    }

    // *** Binding Inspection ***
    /// Dereference all variables in term, including within nested structures like
    /// lists and dictionaries.
    pub fn deref(&self, term: &Term) -> Term {
        Derefer::new(self).fold_term(term.clone())
    }

    /// Get constraints on variable `variable`. If the variable is in a cycle,
    /// the cycle is expressed as a partial.
    pub fn get_constraints(&self, variable: &Symbol) -> Operation {
        match self.get(&Term::from(variable.clone())) {
            None => op!(And),
            Some(Lookup::Bound(val)) => {
                op!(And, term!(op!(Unify, term!(variable.clone()), val.clone())))
            }
            Some(Lookup::Partial(expr)) => expr.clone(),
            Some(Lookup::Cycle(c)) => cycle_constraints(c),
        }
    }

    pub fn variable_state(&self, variable: &Symbol) -> Option<VariableState> {
        self.variable_state_at_point(variable, &self.bsp())
    }

    pub fn variable_state_at_point(&self, variable: &Symbol, bsp: &Bsp) -> Option<VariableState> {
        let index = bsp.bindings_index;
        let mut next = variable;
        while let Some(value) = self.value(next, index) {
            match value.value() {
                Value::Expression(_) => return Some(VariableState::Partial),
                Value::Variable(v) | Value::RestVariable(v) => {
                    if v == variable {
                        return Some(VariableState::Partial);
                    } else {
                        next = v;
                    }
                }
                _ => return Some(VariableState::Bound(value.clone())),
            }
        }
        None
    }

    /// Return all variables used in this binding manager.
    pub fn variables(&self) -> HashSet<Symbol> {
        self.bindings
            .iter()
            .map(|Binding(v, _)| v.clone())
            .collect()
    }

    /// Retrieve an opaque value representing the current state of `BindingManager`.
    /// Can be used to reset state with `backtrack`.
    pub fn bsp(&self) -> Bsp {
        let follower_bsps = self
            .followers
            .iter()
            .map(|(id, f)| (*id, f.bsp()))
            .collect::<HashMap<_, _>>();

        Bsps {
            bindings_index: self.bindings.len(),
            followers: follower_bsps,
        }
    }

    pub fn bindings(&self, include_temps: bool) -> Bindings {
        self.bindings_after(include_temps, &Bsp::default())
    }

    pub fn bindings_after(&self, include_temps: bool, after: &Bsp) -> Bindings {
        let mut bindings = HashMap::new();
        for Binding(var, value) in &self.bindings[after.bindings_index..] {
            if !include_temps && var.is_temporary_var() {
                continue;
            }
            bindings.insert(var.clone(), self.deref(value));
        }
        bindings
    }

    pub fn variable_bindings(&self, variables: &HashSet<Symbol>) -> Bindings {
        let mut bindings = HashMap::new();
        for var in variables.iter() {
            let value = self.value(var, self.bsp().bindings_index);
            if let Some(value) = value {
                bindings.insert(var.clone(), self.deref(value));
            }
        }
        bindings
    }

    /// Get the bindings stack *for debugging purposes only*.
    pub fn bindings_debug(&self) -> &BindingStack {
        &self.bindings
    }

    // *** Followers ***

    pub fn add_follower(&mut self, follower: BindingManager) -> FollowerId {
        let follower_id = self.next_follower_id;
        self.followers.insert(follower_id, follower);
        self.next_follower_id += 1;

        follower_id
    }

    pub fn remove_follower(&mut self, follower_id: &FollowerId) -> Option<BindingManager> {
        self.followers.remove(follower_id)
    }
}

// Private impls.
impl BindingManager {
    /// Bind two variables together.
    pub fn add_binding(&mut self, var: &Symbol, val: Term) {
        self.bindings.push(Binding(var.clone(), val));
    }

    fn lookup(&self, var: &Symbol) -> Option<Term> {
        match self.variable_state(var) {
            Some(VariableState::Bound(val)) => Some(val),
            _ => None,
        }
    }

    /// Look up a variable in the bindings stack and return
    /// a reference to its value if it's bound.
    fn value<'a>(&'a self, var: &Symbol, bsp: usize) -> Option<&'a Term> {
        self.bindings[..bsp]
            .iter()
            .rev()
            .find_map(|Binding(key, val)| (var == key).then(|| val))
    }

    pub fn get<'a>(&'a self, t: &'a Term) -> Option<Lookup<'a>> {
        match t.value() {
            Value::Variable(y) | Value::RestVariable(y) => self
                .value(y, self.bsp().bindings_index)
                .and_then(|t| self.get(t)),
            _ => Some(Lookup::Bound(t)),
        }
    }

    fn _variable_state<'a>(&'a self, y: &Symbol) -> Option<Lookup<'a>> {
        self._variable_state_at_point(y, &self.bsp())
    }

    /// Check the state of `variable` at `bsp`.
    fn _variable_state_at_point<'a>(&'a self, variable: &Symbol, bsp: &Bsp) -> Option<Lookup<'a>> {
        let index = bsp.bindings_index;
        let mut path = vec![variable];
        while let Some(value) = self.value(path.last().unwrap(), index) {
            match value.value() {
                Value::Expression(e) => return Some(Lookup::Partial(e)),
                Value::Variable(v) | Value::RestVariable(v) => {
                    if v == variable {
                        return Some(Lookup::Cycle(path.into_iter().cloned().collect()));
                    } else {
                        path.push(v);
                    }
                }
                _ => return Some(Lookup::Bound(value)),
            }
        }
        None
    }

    fn do_followers<F>(&mut self, mut func: F) -> PolarResult<()>
    where
        F: FnMut(FollowerId, &mut BindingManager) -> PolarResult<()>,
    {
        for (id, follower) in self.followers.iter_mut() {
            func(*id, follower)?
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::formatting::to_polar::ToPolarString;
    type TestResult = PolarResult<()>;

    #[test]
    fn variable_state() {
        let mut bindings = BindingManager::default();

        let x = sym!("x");
        let y = sym!("y");
        let z = sym!("z");

        // Unbound.
        assert_eq!(bindings._variable_state(&x), None,);

        // Bound.
        bindings.add_binding(&x, term!(1));
        assert_eq!(bindings._variable_state(&x), Some(Lookup::Bound(&term!(1))));

        bindings.add_binding(&x, term!(x.clone()));
        assert_eq!(
            bindings._variable_state(&x),
            Some(Lookup::Cycle(vec![x.clone()]))
        );

        // 2-cycle.
        bindings.add_binding(&x, term!(y.clone()));
        bindings.add_binding(&y, term!(x.clone()));
        assert_eq!(
            bindings._variable_state(&x),
            Some(Lookup::Cycle(vec![x.clone(), y.clone()]))
        );
        assert_eq!(
            bindings._variable_state(&y),
            Some(Lookup::Cycle(vec![y.clone(), x.clone()]))
        );

        // 3-cycle.
        bindings.add_binding(&x, term!(y.clone()));
        bindings.add_binding(&y, term!(z.clone()));
        bindings.add_binding(&z, term!(x.clone()));
        assert_eq!(
            bindings._variable_state(&x),
            Some(Lookup::Cycle(vec![x.clone(), y.clone(), z.clone()]))
        );
        assert_eq!(
            bindings._variable_state(&y),
            Some(Lookup::Cycle(vec![y.clone(), z.clone(), x.clone()]))
        );
        assert_eq!(
            bindings._variable_state(&z),
            Some(Lookup::Cycle(vec![z.clone(), x.clone(), y]))
        );

        // Expression.
        bindings.add_binding(&x, term!(op!(And)));
        assert_eq!(
            bindings._variable_state(&x),
            Some(Lookup::Partial(&op!(And)))
        );
    }

    #[test]
    fn test_followers() {
        // Regular bindings
        let mut b1 = BindingManager::default();
        b1.bind(&var!("x"), term!(1)).unwrap();
        b1.bind(&var!("y"), term!(2)).unwrap();

        assert_eq!(
            b1._variable_state(&sym!("x")),
            Some(Lookup::Bound(&term!(1)))
        );
        assert_eq!(
            b1._variable_state(&sym!("y")),
            Some(Lookup::Bound(&term!(2)))
        );

        let b2 = BindingManager::default();
        let b2_id = b1.add_follower(b2);

        b1.bind(&var!("z"), term!(3)).unwrap();

        assert_eq!(
            b1._variable_state(&sym!("x")),
            Some(Lookup::Bound(&term!(1)))
        );
        assert_eq!(
            b1._variable_state(&sym!("y")),
            Some(Lookup::Bound(&term!(2)))
        );
        assert_eq!(
            b1._variable_state(&sym!("z")),
            Some(Lookup::Bound(&term!(3)))
        );

        let b2 = b1.remove_follower(&b2_id).unwrap();
        assert_eq!(b2._variable_state(&sym!("x")), None);
        assert_eq!(b2._variable_state(&sym!("y")), None);
        assert_eq!(
            b2._variable_state(&sym!("z")),
            Some(Lookup::Bound(&term!(3)))
        );

        // Extending cycle.
        let mut b1 = BindingManager::default();
        b1.bind(&var!("x"), var!("y")).unwrap();
        b1.bind(&var!("x"), var!("z")).unwrap();

        let b2 = BindingManager::default();
        let b2_id = b1.add_follower(b2);

        assert!(matches!(
            b1._variable_state(&sym!("x")),
            Some(Lookup::Cycle(_))
        ));
        assert!(matches!(
            b1._variable_state(&sym!("y")),
            Some(Lookup::Cycle(_))
        ));
        assert!(matches!(
            b1._variable_state(&sym!("z")),
            Some(Lookup::Cycle(_))
        ));

        b1.bind(&var!("x"), var!("a")).unwrap();
        if let Some(Lookup::Cycle(c)) = b1._variable_state(&sym!("a")) {
            assert_eq!(
                c,
                vec![sym!("a"), sym!("x"), sym!("y"), sym!("z")],
                "c was {:?}",
                c
            );
        }

        let b2 = b1.remove_follower(&b2_id).unwrap();
        if let Some(Lookup::Cycle(c)) = b2._variable_state(&sym!("a")) {
            assert_eq!(c, vec![sym!("a"), sym!("x")], "c was {:?}", c);
        } else {
            panic!("unexpected");
        }
        if let Some(Lookup::Cycle(c)) = b2._variable_state(&sym!("x")) {
            assert_eq!(c, vec![sym!("x"), sym!("a")], "c was {:?}", c);
        } else {
            panic!("unexpected");
        }

        // Adding constraints to cycles.
        let mut b1 = BindingManager::default();
        b1.bind(&var!("x"), var!("y")).unwrap();
        b1.bind(&var!("x"), var!("z")).unwrap();

        let b2 = BindingManager::default();
        let b2_id = b1.add_follower(b2);

        assert!(matches!(
            b1._variable_state(&sym!("x")),
            Some(Lookup::Cycle(_))
        ));
        assert!(matches!(
            b1._variable_state(&sym!("y")),
            Some(Lookup::Cycle(_))
        ));
        assert!(matches!(
            b1._variable_state(&sym!("z")),
            Some(Lookup::Cycle(_))
        ));

        b1.add_constraint(&term!(op!(Gt, term!(sym!("x")), term!(sym!("y")))))
            .unwrap();

        let b2 = b1.remove_follower(&b2_id).unwrap();

        if let Some(Lookup::Partial(p)) = b1._variable_state(&sym!("x")) {
            assert_eq!(p.to_polar(), "x = y and y = z and z = x and x > y");
        } else {
            panic!("unexpected");
        }

        if let Some(Lookup::Partial(p)) = b2._variable_state(&sym!("x")) {
            assert_eq!(p.to_polar(), "x > y");
        } else {
            panic!("unexpected");
        }
    }

    #[test]
    fn old_deref() -> TestResult {
        let mut bm = BindingManager::default();
        let (x, y, z) = (var!("x"), var!("y"), term!(1));

        // unbound var
        assert_eq!(bm.deref(&x), x);

        // unbound var -> unbound var
        bm.bind(&x, y.clone())?;
        assert_eq!(bm.deref(&x), x);

        // value
        assert_eq!(bm.deref(&z), z.clone());

        // unbound var -> value
        bm.bind(&x, z.clone()).unwrap();
        assert_eq!(bm.deref(&x), z);

        // unbound var -> unbound var -> value
        bm.bind(&x, y.clone()).unwrap();
        bm.bind(&y, z.clone()).unwrap();
        assert_eq!(bm.deref(&x), z);
        Ok(())
    }

    #[test]
    fn deref() {
        let mut bm = BindingManager::default();
        let one = term!(1);
        let two = term!(1);
        let one_var = var!("one");
        let two_var = var!("two");
        bm.bind(&one_var, one.clone()).unwrap();
        bm.bind(&two_var, two.clone()).unwrap();
        let dict = btreemap! {
            sym!("x") => one_var,
            sym!("y") => two_var,
        };
        let list = term!([dict]);
        assert_eq!(
            bm.deref(&list).value().clone(),
            Value::List(vec![term!(btreemap! {
                sym!("x") => one,
                sym!("y") => two,
            })])
        );
    }

    #[test]
    fn bind() {
        let x = var!("x");
        let y = var!("y");
        let zero = term!(0);
        let mut bm = BindingManager::default();
        bm.bind(&x, zero.clone()).unwrap();
        assert_eq!(
            bm.variable_state(x.value().as_symbol().unwrap()),
            Some(VariableState::Bound(zero))
        );
        assert_eq!(bm.variable_state(y.value().as_symbol().unwrap()), None);
    }

    #[test]
    fn test_backtrack_followers() {
        // Regular bindings
        let mut b1 = BindingManager::default();
        b1.bind(&var!("x"), var!("y")).unwrap();
        b1.bind(&var!("z"), var!("x")).unwrap();

        let b2 = BindingManager::default();
        let b2_id = b1.add_follower(b2);

        b1.add_constraint(&term!(op!(Gt, term!(sym!("x")), term!(1))))
            .unwrap();

        let bsp = b1.bsp();

        b1.bind(&var!("a"), term!(sym!("x"))).unwrap();
        assert!(matches!(
            b1.variable_state(&sym!("a")),
            Some(VariableState::Partial),
        ));

        b1.backtrack(&bsp);
        let b2 = b1.remove_follower(&b2_id).unwrap();
        assert!(matches!(b2.variable_state(&sym!("a")), None,));
    }
}
