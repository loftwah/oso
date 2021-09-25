use crate::kb::*;
use crate::polar::*;
use crate::rules::*;
use crate::terms::*;
use crate::counter::*;
use std::collections::HashMap;

pub struct JS(pub String);

// wrong serializer!
impl JsString for Numeric {
    fn to_js(&self) -> String {
        match self {
            Numeric::Integer(i) => format!("{}", i),
            Numeric::Float(f) => format!("{}", f), } } }

pub trait JsString { fn to_js(&self) -> String; }

impl<A> From<A> for JS where A: JsString  {
    fn from(a: A) -> JS { JS(a.to_js()) } }


impl JsString for Term {
    fn to_js(&self) -> String { self.value().to_js() } }

impl<A> JsString for Vec<A> where A: JsString {
    fn to_js(&self) -> String {
        format!("[{}]", self.iter().map(|x| x.to_js()).collect::<Vec<_>>().join(",")) } }

impl JsString for Value {
    fn to_js(&self) -> String { match self {
        Self::List(l) => l.to_js(),
        Self::Number(n) => n.to_js(),
        Self::String(s) => s.to_js(),
        Self::Boolean(b) => b.to_js(),
        Self::Dictionary(d) => d.to_js(),
        Self::Expression(o) => o.to_js(),
        Self::Variable(s) | Self::RestVariable(s) => s.to_js(),
        _ => unimplemented!("don't know how to JS {}", self.to_polar()), } } }


impl JsString for Dictionary {
    fn to_js(&self) -> String { format!( "{{{}}}",
        self.fields.iter().map(|(k, v)| {
            format!("{:?}:{}", k.0, v.to_js())
        }).collect::<Vec<_>>().join(",")) } }

impl JsString for Call {
    fn to_js(&self) -> String { format!(
        "(s=>(kb[\"{}\"].map(f=>f({})).reduce(disj))(s))",
        self.name.0,
        self.args
            .iter()
            .map(|x| x.to_js())
            .collect::<Vec<_>>()
            .join(",")) } }

impl JsString for Pattern {
    fn to_js(&self) -> String {
        match self {
            Self::Dictionary(d) => d.to_js(),
            Self::Instance(i) => i.tag.to_js(),
        }
    }
}

impl JsString for Operation {
    fn to_js(&self) -> String {
        match self.operator {
            Operator::Unify | Operator::Eq | Operator::Assign => format!(
                "join({},{})",
                self.args[0].to_js(),
                self.args[1].to_js()
            ),
            Operator::Neq => format!(
                "split({},{})",
                self.args[0].to_js(),
                self.args[1].to_js()
            ),
            Operator::And => self.args.iter().rev().fold("(x=>x)".to_owned(), |m, i| {
                format!("conj({},{})", i.to_js(), m)
            }),
            Operator::Or => self
                .args
                .iter()
                .rev()
                .fold("(_=>undefined)".to_owned(), |m, i| {
                    format!("disj({},{})", i.to_js(), m)
                }),
            Operator::Not => format!(
                "(s=>({})(Object.assign({{}},s))===undefined?s:undefined)",
                self.args[0].to_js()
            ),
            Operator::Dot => format!(
                "(s=>join({},walk({})(s)[{}])(s))",
                self.args[2].to_js(),
                self.args[0].to_js(),
                self.args[1].to_js()
            ),
            Operator::Isa => format!(
                "(s=>is(walk({})(s),{})?s:undefined)",
                self.args[0].to_js(),
                self.args[1].to_js()
            ),
            _ => unimplemented!("don't know how to compile {:?}", self),
        }
    }
}

impl JsString for Rule {
    fn to_js(&self) -> String {
        let c = Counter::default();
        let gensym = || Symbol(format!("__{}__", c.next()));
        let mut lits: HashMap<String, Term> = HashMap::new();
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
            a.into_iter().map(|p| p.to_js()).collect()
        };
        let params1 = all_vars.join(",");
        let params2 = formal_params
            .iter()
            .map(|p| format!("_{}", p))
            .collect::<Vec<_>>()
            .join(",");
        let body =
            formal_params
            .iter()
            .map(|nom| format!("join({},_{})", nom, nom))
            .fold(self.body.to_js(), |m, i| format!("conj({},{})", i, m));
        format!(
            "(({})=>(({})=>{})({}))",
            params2, params1,
            body,
            all_vars.iter()
                .map(|s| lits.remove(s).map_or_else(||String::from("(new Var())"), |t| t.to_js()))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl JsString for GenericRule {
    fn to_js(&self) -> String {
        format!(
            "[{}]",
            self.rules.values()
                .map(|r| r.to_js())
                .collect::<Vec<_>>()
                .join(",")) } }

impl JsString for KnowledgeBase {
    fn to_js(&self) -> String {
        format!("{{{}}}",
            self.rules.iter()
                .map(|(k, v)| format!("{}:{}", k.to_js(), v.to_js()))
                .collect::<Vec<_>>().join(",")) } }

impl JsString for bool { fn to_js(&self) -> String { format!("{}", self) } }
impl JsString for String { fn to_js(&self) -> String { format!("{:?}", self) } }
impl JsString for i64 { fn to_js(&self) -> String { format!("{}", self) } }
impl JsString for f64 { fn to_js(&self) -> String { format!("{}", self) } }
impl JsString for Symbol { fn to_js(&self) -> String { self.0.clone() } }

impl JsString for Polar {
    fn to_js(&self) -> String {
        format!("((rule,...args)=>{{const kb={};return (kb[rule]||[_=>_=>undefined]).map(f=>f(...args)).reduce(disj)({{}})}})",
            self.kb.read().unwrap().to_js()) } }

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
        assert_eq!(term.to_js(), "[1,2]".to_owned());

        let term: Term = vec!["asdf".into(), "qwer".into(), "zxcv".into()].into();
        assert_eq!(term.to_js(), "[\"asdf\",\"qwer\",\"zxcv\"]".to_owned());

        let term: Term = vec![].into();
        assert_eq!(term.to_js(), "[]".to_owned());

        let term: Term = vec![true.into(), false.into()].into();
        assert_eq!(term.to_js(), "[true,false]".to_owned());

        let term: Term = vec![Value::Dictionary(Dictionary::default()).into()].into();
        assert_eq!(term.to_js(), "[{}]".to_owned())
    }

    #[test]
    fn test_compile_obj() {
        let dict = Dictionary {
            fields: btreemap! { sym!("asdf") => 1.into() },
        };
        let term: Term = Value::Dictionary(dict).into();
        assert_eq!(term.to_js(), "{\"asdf\":1}".to_owned());
        let term: Term = Value::Dictionary(Dictionary::default()).into();
        assert_eq!(term.to_js(), "{}".to_owned());
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
            and.to_js(),
            "conj(join(a,1),conj(join(b,2),(x=>x)))".to_owned()
        )
    }

    #[test]
    fn test_compile_dot() {
        let dot: Term = op!(Dot, var!("a"), str!("qwer"), var!("b")).into();
        assert_eq!(
            dot.to_js(),
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

        assert_eq!(rule.to_js(), "((_a,_b)=>((a,b)=>conj(join(b,_b),conj(join(a,_a),conj(join(a,1),conj(join(b,a),(x=>x))))))((new Var()),(new Var())))".to_owned())
    }

    #[test]
    fn test_compile_generic_rule() {}
}
