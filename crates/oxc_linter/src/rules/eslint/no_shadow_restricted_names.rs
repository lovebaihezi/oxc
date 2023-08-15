use oxc_ast::{
    ast::{
        AssignmentTarget, BindingPattern, Expression, SimpleAssignmentTarget, VariableDeclaration,
        VariableDeclarator,
    },
    AstKind,
};
use oxc_diagnostics::{
    miette::{self, Diagnostic},
    thiserror::Error,
};
use oxc_macros::declare_oxc_lint;
use oxc_span::{Atom, Span};

use crate::{context::LintContext, globals::PRE_DEFINE_VAR, rule::Rule, AstNode};

#[derive(Debug, Error, Diagnostic)]
#[error("eslint(no-shadow-restricted-names): Shadowing of global properties such as 'undefined' is not allowed.")]
#[diagnostic(severity(warning), help("Shadowing of global properties '{0}'."))]
struct NoShadowRestrictedNamesDiagnostic(Atom, #[label] pub Span);

#[derive(Debug, Default, Clone)]
pub struct NoShadowRestrictedNames;

declare_oxc_lint!(
    /// ### What it does
    ///
    /// Disallow redefine the global variables like 'undefined', 'NaN', 'Infinity', 'eval', 'arguments'.
    ///
    /// ### Why is this bad?
    ///
    ///
    /// ### Example
    /// ```javascript
    /// function NaN(){}
    ///
    /// !function(Infinity){};
    ///
    /// var undefined = 5;
    ///
    /// try {} catch(eval){}
    /// ```
    NoShadowRestrictedNames,
    correctness
);

impl Rule for NoShadowRestrictedNames {
    fn run_once<'a>(&self, ctx: &LintContext<'a>) {
        let symbols = ctx.symbols();
        for symbol_id in symbols.iter() {
            let name = symbols.get_name(symbol_id);
            if PRE_DEFINE_VAR.contains_key(name.as_str()) {
                if name.as_str() == "undefined" {
                    if symbols.get_resolved_references(symbol_id).all(|refer| !refer.is_write())
                        && symbols.
                            .get_resolved_references(symbol_id)
                            .map(|refer| ctx.nodes().get_node(refer.node_id()))
                            .all(|v| match v.kind() {
                                AstKind::VariableDeclarator(VariableDeclarator {
                                    init, ..
                                }) => init.is_none(),
                                _ => false,
                            })
                    {
                        ctx.diagnostic(NoShadowRestrictedNamesDiagnostic(
                            name.clone(),
                            symbols.get_span(symbol_id),
                        ))
                    }
                } else {
                    ctx.diagnostic(NoShadowRestrictedNamesDiagnostic(
                        name.clone(),
                        symbols.get_span(symbol_id),
                    ))
                }
            }
        }
    }
}

#[test]
fn test() {
    use crate::tester::Tester;

    let pass = vec![
        ("function foo(bar){ var baz; }", None),
        ("!function foo(bar){ var baz; }", None),
        ("!function(bar){ var baz; }", None),
        ("try {} catch(e) {}", None),
        ("try {} catch(e: undefined) {}", None),
        ("export default function() {}", None),
        ("try {} catch {}", None),
        ("var undefined;", None),
        ("var normal, undefined;", None),
        ("var undefined; doSomething(undefined);", None),
        ("class foo { undefined() { } }", None),
        ("class foo { #undefined() { } }", None),
        ("var normal, undefined; var undefined;", None),
    ];

    let fail = vec![
        ("function NaN(NaN) { var NaN; !function NaN(NaN) { try {} catch(NaN) {} }; }", None),
        ("function undefined(undefined) { !function undefined(undefined) { try {} catch(undefined) {} }; }", None),
        ("function Infinity(Infinity) { var Infinity; !function Infinity(Infinity) { try {} catch(Infinity) {} }; }", None),
        ("function arguments(arguments) { var arguments; !function arguments(arguments) { try {} catch(arguments) {} }; }", None),
        ("function eval(eval) { var eval; !function eval(eval) { try {} catch(eval) {} }; }", None),
        ("var eval = (eval) => { var eval; !function eval(eval) { try {} catch(eval) {} }; }", None),
        ("var {undefined} = obj; var {a: undefined} = obj; var {a: {b: {undefined}}} = obj; var {a, ...undefined} = obj;", None),
        ("var normal, undefined; undefined = 5;", None),
        ("try {} catch(undefined: undefined) {}", None),
        ("var [undefined] = [1]", None),
        ("class undefined { }", None),
        ("class foo { undefined(undefined) { } }", None),
        ("class foo { #undefined(undefined) { } }", None),
    ];

    Tester::new(NoShadowRestrictedNames::NAME, pass, fail).test_and_snapshot();
}
