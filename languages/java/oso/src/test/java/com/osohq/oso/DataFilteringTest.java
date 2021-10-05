package com.osohq.oso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.function.Predicate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DataFilteringTest {
  protected Oso o;

  static class Foo {
    public String id, barId;
    public boolean isFooey;
    public List<Integer> numbers;
    public Foo(String id, String barId, boolean isFooey, List<Integer> numbers) {
      this.id = id;
      this.barId = barId;
      this.isFooey = isFooey;
      this.numbers = numbers;
    }

    public Bar bar() {
      return allBars.stream().filter(b -> b.id == this.barId).findFirst().get();
    }
    public List<Log> logs() {
      return filter(allLogs, l -> l.fooId == this.id);
    }
  }

  static class Bar {
    public String id;
    public boolean isCool, isStillCool;
    public Bar(String id, boolean isCool, boolean isStillCool) {
      this.id = id;
      this.isCool = isCool;
      this.isStillCool = isStillCool;
    }
    public List<Foo> foos() {
      return allFoos.stream().filter(f -> f.barId == this.id)
        .collect(Collectors.toList());
    }
  }

  static class Log {
    public String id, fooId, data;
    public Log(String id, String fooId, String data) {
      this.id = id;
      this.fooId = fooId;
      this.data = data;
    }
    public Foo foo() {
      return allFoos.stream().filter(f -> f.id == this.fooId).findFirst().get();
    }
  }

  private static final Bar
    helloBar = new Bar("hello", true, true),
    goodbyeBar = new Bar("goodbye", false, true),
    hersheyBar = new Bar("hershey", false, false);

  private static final Foo
    somethingFoo = new Foo("something", "hello", false, List.of()),
    anotherFoo = new Foo("another", "hello", true, List.of(1)),
    thirdFoo = new Foo("third", "hello", true, List.of(2)),
    fourthFoo = new Foo("fourth", "goodbye", true, List.of(2, 1));

  private static final Log
    fourthLog = new Log("a", "fourth", "goodbye"),
    thirdLog = new Log("b", "third", "world"),
    anotherLog = new Log("c", "another", "steve");

  private static final List<Foo>
    allFoos = List.of(somethingFoo, anotherFoo, thirdFoo, fourthFoo);
  private static final List<Bar>
    allBars = List.of(helloBar, goodbyeBar, hersheyBar);
  private static final List<Log>
    allLogs = List.of(fourthLog, thirdLog, anotherLog);

  @BeforeEach
  public void setUp() throws Exception {
    try {
      o = new Oso();

      Host.UserType typ,
          bool = o.getClass("Boolean"),
          string = o.getClass("String"),
          integer = o.getClass("Integer"),
          list = o.getClass("List");

      o.configureDataFiltering(
          (q) -> ((List<Object>) q).stream().distinct().collect(Collectors.toList()),
          (a, b) ->
              Stream.concat(((List<Object>) a).stream(), ((List<Object>) b).stream())
                  .collect(Collectors.toList()));

      o.registerClass(
          Foo.class,
          "Foo",
          Map.of(
            "id", string,
            "barId", string,
            "isFooey", bool,
            "numbers", list,
            "bar", new Host.TypeRelation(Host.RelationKind.PARENT, "Bar", "barId", "id"),
            "logs", new Host.TypeRelation(Host.RelationKind.CHILDREN, "Log", "id", "fooId")
          )
        ).buildQuery = (cs) -> filterList(allFoos, cs);

      o.registerClass(
          Bar.class,
          "Bar",
          Map.of(
            "id", string,
            "isCool", bool,
            "isStillCool", bool,
            "foos", new Host.TypeRelation(Host.RelationKind.CHILDREN, "Foo", "id", "barId")
          )
        ).buildQuery = (cs) -> filterList(allBars, cs);

      o.registerClass(
          Log.class,
          "Log",
          Map.of(
            "id", string,
            "fooId", string,
            "data", string,
            "foo", new Host.TypeRelation(Host.RelationKind.PARENT, "Foo", "fooId", "id")
          )
        ).buildQuery = (cs) -> filterList(allLogs, cs);
    } catch (Exception e) {
      throw new Error(e);
    }
  }

  @Test
  public void test_model() {
    o.loadStr("allow(_, _, _: Foo{id: \"something\"});");
    checkAuthz("gwen", "get", Foo.class, List.of(somethingFoo));
    o.clearRules();
    o.loadStr(
        "allow(_, _, _: Foo{id: \"something\"});" +
        "allow(_, _, _: Foo{id: \"another\"});");
    checkAuthz("gwen", "get", Foo.class, List.of(anotherFoo, somethingFoo));
  }


  @Test
  public void test_authorize_scalar_attribute_eq() {
    o.loadStr(
        "allow(_: Bar, \"read\", _: Foo{isFooey: true});" +
        "allow(bar: Bar, \"read\", _: Foo{bar: bar});");
    for (Bar bar : allBars) {
      List<Foo> expected = filter(allFoos, f -> f.isFooey || f.bar() == bar);
      checkAuthz(bar, "read", Foo.class, expected);
    }
  }

  @Test
  public void test_authorize_scalar_attribute_condition() {
    o.loadStr(
      "allow(bar: Bar{isCool: true}, _, _: Foo{bar: bar});" +
      "allow(_: Bar, _, _: Foo{bar: b, isFooey: true}) if b.isCool;" +
      "allow(_: Bar{isStillCool: true}, _, foo: Foo) if"+
      "  foo.bar.isCool = false;");
    for (Bar bar: allBars)
      checkAuthz(bar, "read", Foo.class,
          filter(allFoos, f ->
          f.bar() == bar && bar.isCool ||
          f.bar().isCool && f.isFooey ||
          !f.bar().isCool && bar.isStillCool));
  }

  @Test
  public void test_in_multiple_attribute_relationship() {
    o.loadStr(
      "allow(_, _, _: Foo{isFooey: false});" +
      "allow(bar, _, _: Foo{bar: bar});" +
      "allow(_, _, foo: Foo) if" +
      "  1 in foo.numbers and" +
      "  foo.bar.isCool;" +
      "allow(_, _, foo: Foo) if" +
      "  2 in foo.numbers and" +
      "  foo.bar.isCool;");
    for (Bar bar : allBars)
      checkAuthz(bar, "read", Foo.class,
          filter(allFoos, foo ->
            !foo.isFooey ||
            foo.bar() == bar ||
            foo.bar().isCool && (foo.numbers.contains(1) || foo.numbers.contains(2))));
  }

  @Test
  public void test_nested_relationship_many_single() {
    o.loadStr("allow(log: Log, _, bar: Bar) if log.foo in bar.foos;");
    for (Log log: allLogs)
      checkAuthz(log, "read", Bar.class, filter(allBars, bar ->
            bar.foos().contains(log.foo())));
  }

  @Test
  public void test_nested_relationship_many_many() {
    o.loadStr("allow(log: Log, _, bar: Bar) if foo in bar.foos and log in foo.logs;");
    for (Log log: allLogs) checkAuthz(log, "read", Bar.class, filter(allBars, bar ->
      bar.foos().stream().anyMatch(foo -> foo == log.foo())));
  }

  @Test
  public void test_nested_relationship_many_many_constrained() {
    o.loadStr(
      "allow(log: Log{data:\"steve\"}, _, bar: Bar) if" +
      "  foo in bar.foos and log in foo.logs;");
    for (Log log: allLogs) checkAuthz(log, "read", Bar.class, filter(allBars, bar ->
      log.data == "steve" && bar.foos().stream().anyMatch(foo -> foo == log.foo())));
  }

  @Test
  public void test_partial_in_collection() {
    o.loadStr("allow(bar: Bar, _, foo: Foo) if foo in bar.foos;");
    for (Bar bar : allBars) checkAuthz(bar, "read", Foo.class, bar.foos());
  }

  /* FIXME fails??
  @Test
  public void test_empty_constraints_in() {
    o.loadStr("allow(_, _, foo: Foo) if _ in foo.logs;");
    List<Foo> expected = filter(allFoos, foo -> foo.logs().size() > 0);
    checkAuthz("gwen", "read", Foo.class, expected);
  }
  @Test
  public void test_unify_ins() {
    o.loadStr(
      "allow(_, _, _: Bar{foos: foos}) if" +
      "  foo in foos and goo in foos and foo = goo;");
    checkAuthz("gwen", "read", Bar.class, filter(allBars, bar ->
        bar.foos().size() > 0));
  }

  */

  @Test
  public void test_in_with_constraints_but_no_matching_objects() {
    o.loadStr("allow(_, _, foo: Foo) if log in foo.logs and log.data = \"nope\";");
    checkAuthz("gwen", "read", Foo.class, List.of());
  }

  @Test
  public void test_redundant_in_on_same_field() {
    o.loadStr(
      "allow(_, _, foo: Foo) if" +
      "  m in foo.numbers and" +
      "  n in foo.numbers and" +
      "  m = 1 and n = 2;");
    checkAuthz("gwen", "read", Foo.class, List.of(fourthFoo));
  }

  @Test
  public void test_unify_ins_field_eq() {
    o.loadStr(
      "allow(_, _, _: Bar{foos: foos}) if" +
      "  foo in foos and goo in foos and foo.id = goo.id;");
    checkAuthz("gwen", "read", Bar.class, filter(allBars, bar ->
        !bar.foos().isEmpty()));
  }


  private <T> void checkAuthz(Object actor, Object action, Class<T> resourceCls, List<T> expected) {
    List<T> actual = o.authorizedResources(actor, action, resourceCls);
    assertEquals(expected.size(), actual.size());
    for (T x: actual) assertTrue(expected.contains(x));
  }

  private static <T> List<T> filter(List<T> objs, Predicate<T> pred) {
    return objs.stream().filter(pred).collect(Collectors.toList());
  }

  private static <T> List<T> filterList(List<T> objs, List<FilterPlan.Constraint> cons) {
    return filter(objs, obj -> cons.stream().allMatch((con) -> con.check(obj)));
  }
}
