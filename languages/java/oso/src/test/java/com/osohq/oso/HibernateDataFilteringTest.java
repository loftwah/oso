package com.osohq.oso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.query.Query;

public class HibernateDataFilteringTest {
  protected Oso o;
  static final String labPath = "src/test/resources/lab_policy.polar";
  private SessionFactory sessionFactory;
  private Session session;
  private Lab xeno, meta, stat;
  private Researcher angstrom, bellows, curie, davis, eilenberg;
  private int count;
  @BeforeEach
  public void setUp() throws Exception {
		// A SessionFactory is set up once for an application!
		final StandardServiceRegistry registry = new StandardServiceRegistryBuilder()
				.configure() // configures settings from hibernate.cfg.xml
				.build();
		try {
			sessionFactory = new MetadataSources( registry ).buildMetadata().buildSessionFactory();
		}
		catch (Exception e) {
			// The registry would be destroyed by the SessionFactory, but we had trouble building the SessionFactory
			// so destroy it manually.
			StandardServiceRegistryBuilder.destroy( registry );
      throw e;
		}
    
    count = 0;
    o = new Oso();
    session = sessionFactory.openSession();
    session.beginTransaction();
    xeno = new Lab("Theoretical Xenobiology");
    meta = new Lab("Applied Metaphysics");
    stat = new Lab("Statistical Geology");
    session.save(xeno);
    session.save(meta);
    session.save(stat);
    angstrom = new Researcher("Dr. Angstrom");
    bellows = new Researcher("Dr. Bellows");
    curie = new Researcher("Dr. Curie");
    davis = new Researcher("Dr. Davis");
    eilenberg = new Researcher("Dr. Eilenberg");
    angstrom.setLab(stat);
    bellows.setLab(xeno);
    curie.setLab(stat);
    davis.setLab(xeno);
    eilenberg.setLab(meta);
    session.save(bellows);
    session.getTransaction().commit();

    o.configureDataFiltering(
      (q) -> ((Query) q).list(),
      (a, b) -> combine((Query) a, (Query) b)
    );



    o.registerClass(
      Researcher.class,
      "Researcher",
      Map.of(
        "name", o.getClass("String"),
        "id", o.getClass("Integer"),
        "lab", new Host.TypeRelation(
          Host.RelationKind.PARENT,
          "Lab",
          "lab",
          "id")));

    o.registerClass(
      Lab.class,
      "Lab",
      Map.of(
        "name", o.getClass("String"),
        "id", o.getClass("Integer"),
        "researchers", new Host.TypeRelation(
          Host.RelationKind.CHILDREN,
          "Researcher",
          "id",
          "lab")));

    o.loadStr("allow(dr: Researcher, \"enter\", lab: Lab) if lab = dr.lab;");
    o.loadStr("allow(lab: Lab, \"admit\", dr: Researcher) if lab = dr.lab;");
  }

  @AfterEach
	protected void tearDown() throws Exception {
    if (session != null) session.close();
		if (sessionFactory != null) sessionFactory.close();
	}

  @Test
  public void testOrm() throws Exception {
    Researcher res = session.find(Researcher.class, 1);
    Lab lab = session.find(Lab.class, 1);
    assertEquals(bellows, res);
    assertEquals(xeno, lab);
    assertEquals(lab, res.getLab());
  }

  @Test
  public void testLabAccess() throws Exception {
    Query q = session.createQuery("FROM Lab WHERE id = :id");
    q.setParameter("id", 1);
    System.out.println("=======");
    System.out.println("=======");
    System.out.println("=======");
    System.out.println(q.getQueryString());
    System.out.println("=======");
    System.out.println("=======");
    System.out.println("=======");
    List<Object> labs = o.authorizedResources(curie, "enter", Lab.class);
    assertEquals(1, labs.size());
    assertEquals(stat, labs.get(0));
  }

  private Query combine(Query a, Query b) {
    return a;
  }

  private Query constrain(Query a, String field, Object value) {

    return a;
  }
}
