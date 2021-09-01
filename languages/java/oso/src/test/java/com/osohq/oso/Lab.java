package com.osohq.oso;

import java.util.List;
import java.util.ArrayList;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.OneToMany;

import org.hibernate.annotations.GenericGenerator;

@Entity
public class Lab {
  @Id
  @GeneratedValue
  public int id;
  @Column
  public String name;

  @OneToMany
  public List<Researcher> researchers = new ArrayList();

  public Lab() {}
  public Lab(String name) { this.name = name; }

  public int getId() { return id; }
  public void setId(int id) { this.id = id; }

  public String getName() { return name; }
  public void setName(String name) { this.name = name; }
}
