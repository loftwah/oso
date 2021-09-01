package com.osohq.oso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DataFilteringTest {
  protected Oso o;

  static class Wizard {
    public String name;
    public List<String> books;
    public List<Integer> spellLevels;

    public Wizard(String name, List<String> books, List<Integer> spellLevels) {
      this.name = name;
      this.books = books;
      this.spellLevels = spellLevels;
    }
  }

  static class Familiar {
    public String name;
    public String kind;
    public String wizardName;

    public Familiar(String name, String kind, String wizardName) {
      this.name = name;
      this.kind = kind;
      this.wizardName = wizardName;
    }
  }

  static class Spell {
    public String name;
    public String school;
    public Integer level;

    public Spell(String name, String school, int level) {
      this.name = name;
      this.school = school;
      this.level = level;
    }
  }

  static final String magicPath = "src/test/java/com/osohq/oso/magic_policy.polar";

  static final Wizard
      babaYaga =
          new Wizard(
              "baba yaga",
              List.of("necromancy", "destruction", "summoning"),
              List.of(
                  new Integer(1),
                  new Integer(2),
                  new Integer(3),
                  new Integer(4),
                  new Integer(5),
                  new Integer(6),
                  new Integer(7),
                  new Integer(8))),
      gandalf =
          new Wizard(
              "gandalf",
              List.of("divination", "destruction"),
              List.of(new Integer(1), new Integer(2), new Integer(3), new Integer(4))),
      galadriel =
          new Wizard(
              "galadriel",
              List.of("divination", "thaumaturgy", "inscription"),
              List.of(
                  new Integer(1),
                  new Integer(2),
                  new Integer(3),
                  new Integer(4),
                  new Integer(5),
                  new Integer(6),
                  new Integer(7)));
  static final Familiar shadowfax = new Familiar("shadowfax", "horse", "gandalf"),
      brownJenkin = new Familiar("brown jenkin", "rat", "baba yaga"),
      gimli = new Familiar("gimli", "dwarf", "galadriel"),
      hedwig = new Familiar("hedwig", "owl", "galadriel");

  public static final List<Wizard> wizards = List.of(babaYaga, gandalf, galadriel);
  public static final List<Familiar> familiars = List.of(shadowfax, brownJenkin, gimli, hedwig);
  public static final List<Spell> spells =
      List.of(
          new Spell("teleport other", "thaumaturgy", new Integer(7)),
          new Spell("wish", "thaumaturgy", new Integer(9)),
          new Spell("cure light wounds", "necromancy", new Integer(1)),
          new Spell("identify", "divination", new Integer(1)),
          new Spell("call familiar", "summoning", new Integer(1)),
          new Spell("call ent", "summoning", new Integer(7)),
          new Spell("magic missile", "destruction", new Integer(1)),
          new Spell("liquify organ", "destruction", new Integer(5)),
          new Spell("call dragon", "summoning", new Integer(9)),
          new Spell("know alignment", "divination", new Integer(6)));

  @BeforeEach
  public void setUp() throws Exception {
    try {
      o = new Oso();

      Host.UserType typ,
          string = o.getClass("String"),
          integer = o.getClass("Integer"),
          list = o.getClass("List");

      o.configureDataFiltering(
          (q) -> (List<Object>) q,
          (a, b) ->
              Stream.concat(((List<Object>) a).stream(), ((List<Object>) b).stream())
                  .collect(Collectors.toList()));

      o.registerClass(
                  Wizard.class,
                  "Wizard",
                  Map.of(
                      "name", string,
                      "books", list,
                      "spellLevels", list,
                      "familiars",
                          new Host.TypeRelation(
                              Host.RelationKind.CHILDREN, "Familiar", "name", "wizardName")))
              .buildQuery =
          (cs) -> filterList(wizards, cs);

      o.registerClass(
                  Familiar.class,
                  "Familiar",
                  Map.of(
                      "name", string,
                      "kind", string,
                      "wizardName", string,
                      "wizard",
                          new Host.TypeRelation(
                              Host.RelationKind.PARENT, "Wizard", "wizardName", "name")))
              .buildQuery =
          (cs) -> filterList(familiars, cs);

      o.registerClass(
                  Spell.class,
                  "Spell",
                  Map.of(
                      "name", string,
                      "school", string,
                      "level", integer))
              .buildQuery =
          (cs) -> filterList(spells, cs);

      o.loadFile(magicPath);

    } catch (Exception e) {
      throw new Error(e);
    }
  }

  @Test
  public void testWizardsCanCastTheRightSpells() throws Exception {
    List<Object> spells = o.authorizedResources(gandalf, "cast", Spell.class);
    assertEquals(2, spells.size());
  }

  @Test
  public void testOnlyGandalfCanRideShadowfax() throws Exception {
    List<Object> fams = o.authorizedResources(gandalf, "ride", Familiar.class);
    assertEquals(1, fams.size());
    assertEquals(shadowfax, fams.get(0));

    fams = o.authorizedResources(babaYaga, "ride", Familiar.class);
    assertEquals(0, fams.size());

    fams = o.authorizedResources(galadriel, "ride", Familiar.class);
    assertEquals(0, fams.size());
  }

  @Test
  public void testBrownJenkinCanGroomTheRightPeople() throws Exception {
    List<Object> wizards = o.authorizedResources(brownJenkin, "groom", Wizard.class);
    assertEquals(wizards.size(), 1);
    assertEquals((Wizard) wizards.get(0), babaYaga);

    List<Object> fams = o.authorizedResources(brownJenkin, "groom", Familiar.class);
    assertEquals(3, fams.size());
    assertNotEquals(-1, fams.indexOf(brownJenkin));
    assertNotEquals(-1, fams.indexOf(shadowfax));
    assertNotEquals(-1, fams.indexOf(gimli));
  }

  @Test
  public void testOnlyGaladrielCanInscribeSpells() throws Exception {
    List<Object> spells = o.authorizedResources(galadriel, "inscribe", Spell.class);
    assertNotEquals(spells.size(), 0);

    spells = o.authorizedResources(gandalf, "inscribe", Spell.class);
    assertEquals(spells.size(), 0);
    spells = o.authorizedResources(babaYaga, "inscribe", Spell.class);
    assertEquals(spells.size(), 0);
  }

  private <T> List<T> filterList(List<T> objs, List<FilterPlan.Constraint> cons) {
    return objs.stream()
        .filter((obj) -> cons.stream().allMatch((con) -> con.check(obj)))
        .collect(Collectors.toList());
  }

  private static List<Integer> levels(int l) {
    List<Integer> ls = List.of();
    for (int i = 1; i <= l; i++) ls.add(new Integer(i));
    return ls;
  }
}
