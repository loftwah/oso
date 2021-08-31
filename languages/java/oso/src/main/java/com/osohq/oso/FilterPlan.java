package com.osohq.oso;

import java.util.Map;
import java.util.HashMap;
import org.json.JSONObject;
import org.json.JSONArray;

public class FilterPlan {
  public String className;
  public ResultSet[] resultSets;

  public FilterPlan(JSONObject json, String className) {
    this.className = className;
    JSONArray sets = json.getJSONArray("result_sets");
    this.resultSets = new ResultSet[sets.length()];
    for (int i = 0, j = sets.length(); i < j; i++)
      this.resultSets[i] = new ResultSet(sets.getJSONObject(i));
  }

  class ResultSet {
    public Map<Integer, FilterPlan.Request> requests;
    public int[] resolveOrder;
    public int resultId;

    public ResultSet(JSONObject json) {
      this.resultId = json.getInt("result_id");
      this.requests = new HashMap();
      JSONArray order = json.getJSONArray("resolve_order");
      JSONObject reqs = json.getJSONObject("requests");
      this.resolveOrder = new int[order.length()];
      for (int i = 0, j = order.length(); i < j; i++) {
        this.resolveOrder[i] = order.getInt(i);
        JSONObject req = reqs.getJSONObject(String.valueOf(i));
        this.requests.put(new Integer(i), new Request(req));
      }
    }
  }

  class Request {
    public FilterPlan.Constraint[] constraints;
    public String className;

    public Request(JSONObject json) {
      this.className = json.getString("class_tag");
      JSONArray cons = json.getJSONArray("constraints");
      this.constraints = new FilterPlan.Constraint[cons.length()];
      for (int i = 0, j = cons.length(); i < j; i++)
        this.constraints[i] = new FilterPlan.Constraint(cons.getJSONObject(i));
    }
  }

  // this should go in Constraint, however
  // "static declarations are not allowed in inner classes" :(
  enum ConstraintKind { EQ, NEQ, IN, CONTAINS };
  class Constraint {
    public ConstraintKind kind;
    public String field;
    public ConstraintValue value;

    public Constraint(JSONObject json) {
      this.kind = parseConstraintKind(json.getString("kind"));
      this.field = json.getString("field");
      JSONObject val = json.getJSONObject("value");
      this.value = parseConstraintValue(json.getJSONObject("value"));
    }

    private ConstraintKind parseConstraintKind(String kind) throws Exceptions.OsoException {
      if (kind == "Eq") return FilterPlan.ConstraintKind.EQ;
      if (kind == "Neq") return FilterPlan.ConstraintKind.NEQ;
      if (kind == "In") return FilterPlan.ConstraintKind.IN;
      if (kind == "Contains") return FilterPlan.ConstraintKind.CONTAINS;
      throw new Exceptions.DataFilteringError("Invalid constraint kind: " + kind);
    }

    private ConstraintValue parseConstraintValue(JSONObject value) throws Exceptions.OsoException {
      String key = value.keys().next();
      if (key == "Term") return new Term(value);
      if (key == "Ref") return new Ref(value);
      if (key == "Field") return new Field(value);
      throw new Exceptions.DataFilteringError("Invalid constraint value type: " + key);
    }


    abstract class ConstraintValue {
    }

    class Ref extends ConstraintValue {
      public String field;
      public int resultId;
      public Ref(JSONObject json) {
        this.resultId = json.getInt("result_id");
        this.field = json.getString("field");
      }
    }

    class Field extends ConstraintValue {
      public String field;
      public Field(JSONObject json) {
        this.field = json.getString("field");
      }
    }

    class Term extends ConstraintValue {
      public JSONObject value;
      public Term(JSONObject json) {
        this.value = json;
      }
    }
  }
}
