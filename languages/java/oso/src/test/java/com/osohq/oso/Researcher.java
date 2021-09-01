package com.osohq.oso;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.OneToOne;

import org.hibernate.annotations.GenericGenerator;


@Entity
public class Researcher {
  @Id
  @GeneratedValue
  public int id;
  @Column
  public String name;
  @OneToOne
  public Lab lab;

  public Researcher() {}
  public Researcher(String name) { this.name = name; }

  public int getId() { return id; }
  public void setId(int id) { this.id = id; }

  public String getName() { return name; }
  public void setName(String name) { this.name = name; }

  public Lab getLab() { return lab; }
  public void setLab(Lab lab) { this.lab = lab; }
}
