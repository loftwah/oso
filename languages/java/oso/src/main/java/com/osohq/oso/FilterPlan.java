package com.osohq.oso;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import org.json.JSONObject;
import org.json.JSONArray;

public class FilterPlan {
  public String className;
  public ResultSet[] resultSets;
  private Host host;

  public FilterPlan(Host host, JSONObject json, String className) {
    this.host = host;
    this.className = className;
    JSONArray sets = json.getJSONArray("result_sets");
    this.resultSets = new ResultSet[sets.length()];
    for (int i = 0, j = sets.length(); i < j; i++)
      this.resultSets[i] = new ResultSet(sets.getJSONObject(i));
  }

  public Object buildQuery() {
    BiFunction<Object, Object, Object> combine = null;
    List<Object> queries = new ArrayList();
    for (ResultSet rs : resultSets) {
      HashMap<Integer, List<Object>> setResults = new HashMap();
      for (int i : rs.resolveOrder) {
        Request req = rs.requests.get(new Integer(i));
        for (Constraint con : req.constraints)
          con.ground(this.host, setResults);
        Host.UserType type = this.host.types.get(this.className);
        Object query = type.buildQuery.apply(req.constraints);
        if (i != rs.resultId) {
          setResults.put(new Integer(i), type.execQuery.apply(query));
        } else {
          combine = type.combineQuery;
          queries.add(query);
        }
      }
    }

    if (queries.size() == 0) return null;
    final BiFunction<Object, Object, Object> merge = combine;
    return queries.stream().reduce((a, b) -> merge.apply(a, b));
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
    public List<FilterPlan.Constraint> constraints;
    public String className;

    public Request(JSONObject json) {
      this.className = json.getString("class_tag");
      JSONArray cons = json.getJSONArray("constraints");
      this.constraints = new ArrayList();
      for (int i = 0, j = cons.length(); i < j; i++)
        this.constraints.add(new FilterPlan.Constraint(cons.getJSONObject(i)));
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

    public void ground(Host host, Map<Integer, List<Object>> setResults) throws Exceptions.DataFilteringError {
      if (this.value instanceof Ref) {
        Ref ref = (Ref) this.value;
        List<Object> val = setResults.get(new Integer(ref.resultId));
        if (ref.field != null) for (int i = 0, j = val.size(); i < j; i++) try {
          Object v = val.get(i);
          val.set(i, v.getClass().getField(ref.field).get(v));
        } catch (NoSuchFieldException|IllegalAccessException e) {
          throw new Exceptions.DataFilteringError("Couldn't read field " + ref.field + " of result set " + String.valueOf(ref.resultId));
        }
        this.value = new Term(host.toPolarTerm(val));
      }
    }


    public boolean check(Object obj) {
      Object val;

      try {
        if (value instanceof Field)
          val = obj.getClass().getField(value.field).get(obj);
        else
          val = value;

        if (field != null)
          obj = obj.getClass().getField(field).get(obj);
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new Exceptions.DataFilteringError("Error reading field from class");
      }

      switch (kind) {
        case EQ: return val.equals(obj);
        case NEQ: return !val.equals(obj);
        case IN: return ((List<Object>)val).indexOf(obj) > -1;
        case CONTAINS: return ((List<Object>)obj).indexOf(val) > -1;
        default:
          throw new Exceptions.DataFilteringError("Unimplemented");
      }
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
      public String field;
    }

    class Ref extends ConstraintValue {
      public int resultId;
      public Ref(JSONObject json) {
        this.resultId = json.getInt("result_id");
        this.field = json.getString("field");
      }
    }

    class Field extends ConstraintValue {
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
