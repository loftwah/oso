package com.osohq.oso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DataFilteringTest {
  protected Oso o;

  enum FamiliarKind { Horse, Rat, Owl, Dwarf }
  enum MagicSchool { Thaumaturgy, Necromancy, Summoning, Divination, Destruction, Inscription }
  static class Wizard {
    public String name;
    public List<MagicSchool> books;
    public List<Integer> spellLevels;

    public Wizard(String name, List<MagicSchool> books, List<Integer> spellLevels) {
      this.name = name;
      this.books = books;
      this.spellLevels = spellLevels;
    }
  }

  static class Familiar {
    public String name;
    public FamiliarKind kind;
    public String wizardName;

    public Familiar(String name, FamiliarKind kind, String wizardName) {
      this.name = name;
      this.kind = kind;
      this.wizardName = wizardName;
    }
  }

  static class Spell {
    String name;
    MagicSchool school;
    Integer level;

    public Spell(String name, MagicSchool school, int level) {
      this.name = name;
      this.school = school;
      this.level = level;
    }
  }

  static final String magicPath = "src/test/java/com/osohq/oso/magic_policy.polar";

  static final Wizard
    babaYaga = new Wizard(
      "baba yaga",
      List.of(MagicSchool.Necromancy, MagicSchool.Destruction, MagicSchool.Summoning),
      List.of(
        new Integer(1),
        new Integer(2),
        new Integer(3),
        new Integer(4),
        new Integer(5),
        new Integer(6),
        new Integer(7),
        new Integer(8))),
    gandalf = new Wizard(
      "gandalf",
      List.of(MagicSchool.Divination, MagicSchool.Destruction),
      List.of(
        new Integer(1),
        new Integer(2),
        new Integer(3),
        new Integer(4))),
    galadriel = new Wizard(
      "galadriel",
      List.of(MagicSchool.Divination, MagicSchool.Thaumaturgy, MagicSchool.Inscription),
      List.of(
        new Integer(1),
        new Integer(2),
        new Integer(3),
        new Integer(4),
        new Integer(5),
        new Integer(6),
        new Integer(7)));

  static final Familiar
    shadowfax = new Familiar(
      "shadowfax",
      FamiliarKind.Horse,
      "gandalf"),
    brownJenkin = new Familiar(
      "brown jenkin",
      FamiliarKind.Rat,
      "baba yaga"),
    gimli = new Familiar(
      "gimli",
      FamiliarKind.Dwarf,
      "galadriel"),
    hedwig = new Familiar(
      "hedwig",
      FamiliarKind.Owl,
      "galadriel");

  
  protected List<Wizard> wizards = List.of(babaYaga, gandalf, galadriel);
  protected List<Familiar> familiars = List.of(shadowfax, brownJenkin, gimli, hedwig);
  protected List<Spell> spells = List.of(
    new Spell("teleport other",    MagicSchool.Thaumaturgy, new Integer(7)),
    new Spell("wish",              MagicSchool.Thaumaturgy, new Integer(9)),
    new Spell("cure light wounds", MagicSchool.Necromancy,  new Integer(1)),
    new Spell("identify",          MagicSchool.Divination,  new Integer(1)),
    new Spell("call familiar",     MagicSchool.Summoning,   new Integer(1)),
    new Spell("call ent",          MagicSchool.Summoning,   new Integer(7)),
    new Spell("magic missile",     MagicSchool.Destruction, new Integer(1)),
    new Spell("liquify organ",     MagicSchool.Destruction, new Integer(5)),
    new Spell("call dragon",       MagicSchool.Summoning,   new Integer(9)),
    new Spell("know alignment",    MagicSchool.Divination,  new Integer(6)));

  @BeforeEach
  public void setUp() throws Exception {
    try {
      o = new Oso();

      Host.UserType
        typ,
        string = o.getClass("String"),
        integer = o.getClass("Integer"),
        list = o.getClass("List"),
        kind = o.registerClass(FamiliarKind.class),
        school = o.registerClass(MagicSchool.class);

      o.configureDataFiltering(
        (q) -> (List<Object>) q,
        (a, b) -> Stream.concat(((List<Object>)a).stream(), ((List<Object>)b).stream()).collect(Collectors.toList())
      );

      o.registerClass(
        Wizard.class,
        "Wizard",
        Map.of(
          "name", string,
          "books", list,
          "spellLevels", list,
          "familiars", new Host.TypeRelation(
            Host.RelationKind.CHILDREN,
            "Familiar",
            "name",
            "wizardName"))
      ).buildQuery = (cs) -> filterList(wizards, cs);

      o.registerClass(
        Familiar.class,
        "Familiar",
        Map.of(
          "name", string,
          "kind", kind,
          "wizardName", string,
          "wizard", new Host.TypeRelation(
            Host.RelationKind.PARENT,
            "Wizard",
            "wizardName",
            "name"))
      ).buildQuery = (cs) -> filterList(familiars, cs);

      o.registerClass(
        Spell.class,
        "Spell",
        Map.of(
          "name", string,
          "school", school,
          "level", integer)
      ).buildQuery = (cs) -> filterList(spells, cs);

      o.loadFile(magicPath);

    } catch (Exception e) {
      throw new Error(e);
    }
  }

  @Test
  public void testWizardsCanCastTheRightSpells() throws Exception {
    List<Object> spells = o.authorizedResources(gandalf, "cast", Spell.class);
    assertEquals(4, spells.size());
  }


  private<T> List<T> filterList(List<T> objs, List<FilterPlan.Constraint> cons) {
    return objs.stream().filter((obj) -> cons.stream().allMatch((con) -> con.check(obj))).collect(Collectors.toList());
  }

  private static List<Integer> levels(int l) {
    List<Integer> ls = List.of();
    for (int i = 1; i <= l; i++)
      ls.add(new Integer(i));
    return ls;
  }
}
