use crate::terms::*;
use crate::rules::*;
use crate::sources::*;
use crate::kb::*;
use crate::polar::*;

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
        JS(format!("{{{}}}", self.fields.iter().fold(String::new(), |mut out, (k, v)| {
            out.push_str(&format!("{:?}:{},", k.0, v.compile().0));
            out
        })))
    }
}

impl Compile<JS> for Symbol {
    fn compile(&self) -> JS {
        JS(self.0.clone())
    }
}

impl Compile<JS> for Call {
    fn compile(&self) -> JS {
        let args = self.args.iter().map(|x| x.compile().0).collect::<Vec<_>>().join(",");
        JS(format!("{}({})", self.name.0, args))
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
            Operator::Unify | Operator::Eq | Operator::Assign =>
                format!("join({},{})", self.args[0].compile().0, self.args[1].compile().0),
            Operator::Neq =>
                format!("split({},{})", self.args[0].compile().0, self.args[1].compile().0),
            Operator::And if self.args.len() == 0 => "(x=>x)".to_owned(),
            Operator::And => {
                let args = self.args.iter().rev().map(|x| x.compile().0);
                args.reduce(|m, i| format!("conj({},{})", i, m)).unwrap()
            }
            Operator::Or if self.args.len() == 0 => "(_=>undefined)".to_owned(),
            Operator::Or  => {
                let args = self.args.iter().rev().map(|x| x.compile().0);
                args.reduce(|m, i| format!("disj({},{})", i, m)).unwrap()
            }
            Operator::Dot =>
                format!("(s=>walk({})(s)[walk({})(s)])", self.args[0].compile().0, self.args[1].compile().0),
            Operator::Isa =>
                format!("(s=>is(walk({})(s),{})?s:undefined)", self.args[0].compile().0, self.args[1].compile().0),
            _ => unimplemented!("don't know how to compile {:?}", self)
        })
    }
}

impl<A> Compile<JS> for Vec<A> where A: Compile<JS> {
    fn compile(&self) -> JS {
        JS(format!("[{}]", self.iter().fold(String::new(), |mut out, i| {
            out.push_str(&format!("{},", i.compile().0));
            out
        })))
    }
}

impl Compile<JS> for Term {
    fn compile(&self) -> JS {
        self.value().compile()
    }
}

impl Compile<JS> for Rule {
    fn compile(&self) -> JS {
        let params = self.params.iter()
            .map(|p| p.parameter.compile().0)
            .collect::<Vec<_>>();
        let params1 = params.join(",");
        let params2 = params.iter()
            .map(|p| format!("_{}", p))
            .collect::<Vec<_>>()
            .join(",");
        let body = self.params.iter().rev()
            .map(|p| {
                let nom = p.parameter.compile().0;
                format!("join({},_{})", nom, nom)
            })
            .fold(self.body.compile().0, |m, i| format!("conj({},{})", i, m));
        let vars = self.params.iter()
            .map(|_| "(new Var())".to_owned())
            .collect::<Vec<_>>()
            .join(",");
        JS(format!("(({})=>(({})=>{})({}))", params2, params1, body, vars))
    }
}

impl Compile<JS> for GenericRule {
    fn compile(&self) -> JS {
        let ary = self.rules.values().map(|r| r.compile().0).collect::<Vec<_>>().join(",");
        JS(format!("[{}]", ary))
    }
}

impl Compile<JS> for KnowledgeBase {
    fn compile(&self) -> JS {
        let fields = self.rules.iter().map(|(k, v)| format!("{}:{}", k.compile().0, v.compile().0));
        JS(format!("{{{}}}", fields.collect::<Vec<_>>().join(",")))
    }
}

impl Compile<JS> for Polar {
    fn compile(&self) -> JS {
        let kb = self.kb.read().unwrap().compile().0;
        JS(format!("(((rule,...args)=>({})[rule].map(f=>f(...args)).reduce(disj)({{}})))", kb))
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
            _ => unimplemented!("don't know how to compile {:?}", self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            fields: btreemap! { sym!("asdf") => 1.into() }
        };
        let term: Term = Value::Dictionary(dict).into();
        assert_eq!(term.compile().0, "{\"asdf\":1,}".to_owned());
        let term: Term = Value::Dictionary(Dictionary::default()).into();
        assert_eq!(term.compile().0, "{}".to_owned());
    }

    #[test]
    fn test_compile_and() {
        let and: Term = op!(And, op!(Unify, var!("a"), 1.into()).into(), op!(Unify, var!("b"), 2.into()).into()).into();
        assert_eq!(and.compile().0, "conj(join(a,1),join(b,2))".to_owned())
    }

    #[test]
    fn test_compile_dot() {
        let dot: Term = op!(Dot, var!("a"), str!("qwer")).into();
        assert_eq!(dot.compile().0, "a[\"qwer\"]".to_owned())
    }

    #[test]
    fn test_compile_rule() {
        let rule = Rule {
            name: sym!("a_rule"),
            params: vec![Parameter { parameter: var!("a"), specializer: None },
                         Parameter { parameter: var!("b"), specializer: None }],
            body: op!(And, op!(Unify, var!("a"), 1.into()).into(),
                           op!(Unify, var!("b"), var!("a")).into()).into(),
            source_info: SourceInfo::Test,
        };

        assert_eq!(rule.compile().0, "((_a,_b)=>((a,b)=>conj(join(a,_a),conj(join(b,_b),conj(join(a,1),join(b,a)))))(new Var(),new Var()))".to_owned())
    }

    #[test]
    fn test_compile_generic_rule() {
    }
}
