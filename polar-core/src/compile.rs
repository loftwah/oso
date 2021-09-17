use crate::kb::*;
use crate::polar::*;
use crate::rules::*;
use crate::terms::*;
use crate::counter::*;
use std::collections::HashMap;

pub struct JS(pub String);
pub trait Compile<T> {
    fn compile(&self) -> T;
}

impl Compile<JS> for Numeric {
    fn compile(&self) -> JS {
        match self {
            Self::Integer(i) => JS(format!("{}", i)),
            Self::Float(f) => JS(format!("{}", f)),
        }
    }
}

impl Compile<JS> for String {
    fn compile(&self) -> JS {
        JS(format!("{:?}", self))
    }
}

impl Compile<JS> for bool {
    fn compile(&self) -> JS {
        JS(format!("{:?}", self))
    }
}

impl Compile<JS> for Dictionary {
    fn compile(&self) -> JS {
        JS(format!(
            "{{{}}}",
            self.fields.iter().fold(String::new(), |mut out, (k, v)| {
                out.push_str(&format!("{:?}:{},", k.0, v.compile().0));
                out
            })
        ))
    }
}

impl Compile<JS> for Symbol {
    fn compile(&self) -> JS {
        JS(self.0.clone())
    }
}

impl Compile<JS> for Call {
    fn compile(&self) -> JS {
        let args = self
            .args
            .iter()
            .map(|x| x.compile().0)
            .collect::<Vec<_>>()
            .join(",");
        JS(format!(
            "(s=>(kb[\"{}\"].map(f=>f({})).reduce(disj))(s))",
            self.name.0, args
        ))
    }
}

impl Compile<JS> for Pattern {
    fn compile(&self) -> JS {
        match self {
            Self::Dictionary(d) => d.compile(),
            Self::Instance(i) => i.tag.compile(),
        }
    }
}

impl Compile<JS> for Operation {
    fn compile(&self) -> JS {
        JS(match self.operator {
            Operator::Unify | Operator::Eq | Operator::Assign => format!(
                "join({},{})",
                self.args[0].compile().0,
                self.args[1].compile().0
            ),
            Operator::Neq => format!(
                "split({},{})",
                self.args[0].compile().0,
                self.args[1].compile().0
            ),
            Operator::And => self.args.iter().rev().fold("(x=>x)".to_owned(), |m, i| {
                format!("conj({},{})", i.compile().0, m)
            }),
            Operator::Or => self
                .args
                .iter()
                .rev()
                .fold("(_=>undefined)".to_owned(), |m, i| {
                    format!("disj({},{})", i.compile().0, m)
                }),
            Operator::Not => format!(
                "(s=>({})(Object.assign({{}},s))===undefined?s:undefined)",
                self.args[0].compile().0
            ),
            Operator::Dot => format!(
                "(s=>join({},walk({})(s)[{}])(s))",
                self.args[2].compile().0,
                self.args[0].compile().0,
                self.args[1].compile().0
            ),
            Operator::Isa => format!(
                "(s=>is(walk({})(s),{})?s:undefined)",
                self.args[0].compile().0,
                self.args[1].compile().0
            ),
            _ => unimplemented!("don't know how to compile {:?}", self),
        })
    }
}

impl<A> Compile<JS> for Vec<A>
where
    A: Compile<JS>,
{
    fn compile(&self) -> JS {
        JS(format!(
            "[{}]",
            self.iter().fold(String::new(), |mut out, i| {
                out.push_str(&format!("{},", i.compile().0));
                out
            })
        ))
    }
}

impl Compile<JS> for Term {
    fn compile(&self) -> JS {
        self.value().compile()
    }
}

impl Compile<JS> for Rule {
    fn compile(&self) -> JS {
        let counter = Counter::default();
        let mut lits: HashMap<String, Term> = HashMap::new();
        let gensym = || Symbol(format!("__{}__", counter.next()));
        let body = self.body.value().as_expression().unwrap().clone();
        let formal_params = self.params.iter().map(|p| match p.parameter.value().as_symbol() {
            Ok(s) => s.clone(),
            _ => {
                let sym = gensym();
                lits.insert(sym.0.clone(), p.parameter.clone());
                sym
            }
        }).collect::<Vec<_>>();
        let all_vars: Vec<_> = {
            let mut a = formal_params.clone();
            for v in body.variables() {
                if !a.iter().any(|x| *x == v) {
                    a.push(v)
                }
            }
            a.into_iter().map(|p| p.compile().0).collect()
        };
        let params1 = all_vars.join(",");
        let params2 = formal_params
            .iter()
            .map(|p| format!("_{}", p))
            .collect::<Vec<_>>()
            .join(",");
        let body = formal_params
            .iter()
            .map(|nom| format!("join({},_{})", nom, nom))
            .fold(self.body.compile().0, |m, i| format!("conj({},{})", i, m));
        let vars = all_vars
            .iter()
            .map(|s| {
                if let Some(t) = lits.remove(s) {
                    t.compile().0
                } else {
                    "(new Var())".to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        JS(format!(
            "(({})=>(({})=>{})({}))",
            params2, params1, body, vars
        ))
    }
}

impl Compile<JS> for GenericRule {
    fn compile(&self) -> JS {
        let ary = self
            .rules
            .values()
            .map(|r| r.compile().0)
            .collect::<Vec<_>>()
            .join(",");
        JS(format!("[{}]", ary))
    }
}

impl Compile<JS> for KnowledgeBase {
    fn compile(&self) -> JS {
        let fields = self
            .rules
            .iter()
            .map(|(k, v)| format!("{}:{}", k.compile().0, v.compile().0));
        JS(format!("{{{}}}", fields.collect::<Vec<_>>().join(",")))
    }
}

impl Compile<JS> for Polar {
    fn compile(&self) -> JS {
        let kb = self.kb.read().unwrap().compile().0;
        JS(format!("((rule,...args)=>{{const kb={};return kb[rule].map(f=>f(...args)).reduce(disj)({{}})}})", kb))
    }
}

impl Compile<JS> for Value {
    fn compile(&self) -> JS {
        match self {
            Self::Number(n) => n.compile(),
            Self::String(s) => s.compile(),
            Self::Boolean(b) => b.compile(),
            Self::Dictionary(d) => d.compile(),
            Self::List(l) => l.compile(),
            Self::Variable(s) => s.compile(),
            Self::Call(c) => c.compile(),
            Self::Expression(x) => x.compile(),
            Self::Pattern(p) => p.compile(),
            _ => unimplemented!("don't know how to compile {:?}", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::*;

    impl From<&str> for Value {
        fn from(other: &str) -> Self {
            Value::String(other.to_owned())
        }
    }
    #[test]
    fn test_compile_list() {
        let term: Term = vec![1.into(), 2.into()].into();
        assert_eq!(term.compile().0, "[1,2,]".to_owned());

        let term: Term = vec!["asdf".into(), "qwer".into(), "zxcv".into()].into();
        assert_eq!(term.compile().0, "[\"asdf\",\"qwer\",\"zxcv\",]".to_owned());

        let term: Term = vec![].into();
        assert_eq!(term.compile().0, "[]".to_owned());

        let term: Term = vec![true.into(), false.into()].into();
        assert_eq!(term.compile().0, "[true,false,]".to_owned());

        let term: Term = vec![Value::Dictionary(Dictionary::default()).into()].into();
        assert_eq!(term.compile().0, "[{},]".to_owned())
    }

    #[test]
    fn test_compile_obj() {
        let dict = Dictionary {
            fields: btreemap! { sym!("asdf") => 1.into() },
        };
        let term: Term = Value::Dictionary(dict).into();
        assert_eq!(term.compile().0, "{\"asdf\":1,}".to_owned());
        let term: Term = Value::Dictionary(Dictionary::default()).into();
        assert_eq!(term.compile().0, "{}".to_owned());
    }

    #[test]
    fn test_compile_and() {
        let and: Term = op!(
            And,
            op!(Unify, var!("a"), 1.into()).into(),
            op!(Unify, var!("b"), 2.into()).into()
        )
        .into();
        assert_eq!(
            and.compile().0,
            "conj(join(a,1),conj(join(b,2),(x=>x)))".to_owned()
        )
    }

    #[test]
    fn test_compile_dot() {
        let dot: Term = op!(Dot, var!("a"), str!("qwer"), var!("b")).into();
        assert_eq!(
            dot.compile().0,
            "(s=>join(b,walk(a)(s)[\"qwer\"])(s))".to_owned()
        )
    }

    #[test]
    fn test_compile_rule() {
        let rule = Rule {
            name: sym!("a_rule"),
            params: vec![
                Parameter {
                    parameter: var!("a"),
                    specializer: None,
                },
                Parameter {
                    parameter: var!("b"),
                    specializer: None,
                },
            ],
            body: op!(
                And,
                op!(Unify, var!("a"), 1.into()).into(),
                op!(Unify, var!("b"), var!("a")).into()
            )
            .into(),
            source_info: SourceInfo::Test,
        };

        assert_eq!(rule.compile().0, "((_a,_b)=>((a,b)=>conj(join(b,_b),conj(join(a,_a),conj(join(a,1),conj(join(b,a),(x=>x))))))((new Var()),(new Var())))".to_owned())
    }

    #[test]
    fn test_compile_generic_rule() {}
}
