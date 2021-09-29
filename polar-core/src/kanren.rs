use super::counter::Counter;
use super::terms::*;
use std::collections::HashMap;
use std::rc::Rc;

type Nom = u64;

pub trait Run<S> {
    fn run(&self, _state: S) -> Option<S>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Goal {
    Equal(Term, Term),
//    Unequal(Term, Term),
    Conj(Rc<Goal>, Rc<Goal>),
    Disj(Rc<Goal>, Rc<Goal>),
    Pass,
    Fail,
}

#[derive(Clone, Debug, Default)]
pub struct State {
    subst: HashMap<String, Term>,
//    constraints: HashMap<String, HashSet<Con>>,
    counter: Counter,
}

impl State {
    fn bind(mut self, var: String, val: Term) -> Option<Self> {
        self.subst.insert(var, val);
        Some(self)
    }

    fn walk(&self, a: Term) -> Term {
        if let Value::Variable(s) = a.value() {
            if let Some(t) = self.subst.get(&s.0) {
                return self.walk(t.clone())
            }
        }
        a
    }

    fn unify(self, a: Term, b: Term) -> Option<Self> {
        let (a, b) = (self.walk(a), self.walk(b));
        match (a.value(), b.value()) {
            (a, b) if a == b => Some(self),
            (Value::Variable(a), _) => self.bind(a.0.clone(), b),
            (_, Value::Variable(b)) => self.bind(b.0.clone(), a),
            (Value::List(a), Value::List(b)) if a.len() == b.len() => {
                a.iter().zip(b.iter()).fold(Some(self), |s, (a, b)| s.and_then(|s| s.unify(a.clone(), b.clone())))
            }
            _ => None,
        }
    }

    fn reify(self) -> HashMap<String, Term> {
        let mut out = HashMap::new();
        for k in self.subst.keys() {
            out.insert(k.clone(), self.walk(var!(k)));
        }
        out
    }
}


impl Run<State> for Goal {
    fn run(&self, s: State) -> Option<State> {
        match self {
            Self::Equal(a, b) => s.unify(a.clone(), b.clone()),
//            Unequal(a, b) => term_disunify(a, b, state),
            Self::Conj(a, b) => a.run(s).and_then(|s| b.run(s)),
            Self::Disj(a, b) => a.run(s.clone()).or_else(|| b.run(s)),
            Self::Pass => Some(s),
            Self::Fail => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::*;

    #[test]
    fn test_conj() {
        let one = Term::from(1);
        let goal1 = Goal::Equal(var!("x"), var!("y"));
        let goal2 = Goal::Equal(var!("x"), one.clone());
        let goal3 = Goal::Conj(Rc::new(goal1), Rc::new(goal2));
        let out = goal3.run(State::default()).unwrap().reify();
        let val = Some(&one);
        assert_eq!(out.get("x"), val);
        assert_eq!(out.get("y"), val);
    }
}

