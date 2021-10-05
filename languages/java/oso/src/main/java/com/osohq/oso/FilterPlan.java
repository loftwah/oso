package com.osohq.oso;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.stream.Collectors;

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
      this.resultSets[i] = new ResultSet(host, sets.getJSONObject(i));
  }

  private static class Partition<T> {
    public List<T> yes, no;
    public Partition(List<T> coll, Predicate<T> pred) {
      yes = new ArrayList();
      no = new ArrayList();
      for (T t: coll) (pred.test(t) ? yes : no).add(t);
    }
  }

  private <T, U> Map<U, List<T>> groupBy(List<T> coll, Function<T, U> fun) {
    HashMap<U, List<T>> out = new HashMap();
    for (T it: coll) {
      U res = fun.apply(it);
      List<T> l = out.get(res);
      if (l == null) {
        l = new ArrayList();
        out.put(res, l);
      }
      l.add(it);
    }
    return out;
  }

  private List<Constraint> groundFilters(HashMap<Integer, List<Object>> setResults, List<Constraint> fils) {
    Partition<Constraint>
      p1 = new Partition(fils, fil -> ((Constraint)fil).value.getClass() == Ref.class),
      p2 = new Partition(p1.yes, fil -> ((Constraint)fil).kind == ConstraintKind.IN || ((Constraint)fil).kind == ConstraintKind.EQ);
    List<Constraint> rest = p1.no, yrefs = p2.yes, nrefs = p2.no;
    for (List<Constraint> refs: yrefs)
      for (Map.Entry<Integer, List<Constraint>> ent: groupBy(refs, fil -> ((Ref)((Constraint)fil).value).resultId).entrySet()) {
        List<Constraint> fs = ent.getValue();
        List<Object> value = new Term(setResults.get(ent.getKey()).stream().map(r ->
            fs.stream().map(f ->
              r.getClass().getField(((Ref)((Constraint)f).value).field).get(r))
            .collect(Collectors.toList())).collect(Collectors.toList()));
        rest.add(new Constraint(host, ConstraintKind.IN, fs.stream().map(f -> f.field).collect(Collectors.toList()), value));
      }
    return rest;
  }

  public Object buildQuery() {
    BiFunction<Object, Object, Object> combine = null;
    List<Object> queries = new ArrayList();
    for (ResultSet rs : resultSets) {
      HashMap<Integer, List<Object>> setResults = new HashMap();
      for (int i : rs.resolveOrder) {
        Request req = rs.requests.get(new Integer(i));
        for (Constraint con : req.constraints) con.ground(setResults);
        Host.UserType type = this.host.types.get(req.className);
        Object query = type.buildQuery.apply(req.constraints);
        if (i != rs.resultId) {
          List<Object> result_set = type.execQuery.apply(query);
          setResults.put(new Integer(i), result_set);
        } else {
          combine = type.combineQuery;
          queries.add(query);
        }
      }
    }

    if (queries.size() == 0) return null;
    final BiFunction<Object, Object, Object> merge = combine;
    return queries.stream().reduce((a, b) -> merge.apply(a, b)).get();
  }

  class ResultSet {
    public Map<Integer, FilterPlan.Request> requests;
    public int[] resolveOrder;
    public int resultId;

    public ResultSet(Host host, JSONObject json) {
      this.resultId = json.getInt("result_id");
      this.requests = new HashMap();
      JSONArray order = json.getJSONArray("resolve_order");
      JSONObject reqs = json.getJSONObject("requests");
      this.resolveOrder = new int[order.length()];
      for (int i = 0, j = order.length(); i < j; i++) {
        int k = order.getInt(i);
        this.resolveOrder[i] = k;
        JSONObject req = reqs.getJSONObject(String.valueOf(k));
        this.requests.put(new Integer(k), new Request(host, req));
      }
    }
  }

  class Request {
    public List<FilterPlan.Constraint> constraints;
    public String className;

    public Request(Host host, JSONObject json) {
      this.className = json.getString("class_tag");
      JSONArray cons = json.getJSONArray("constraints");
      this.constraints = new ArrayList();
      for (int i = 0, j = cons.length(); i < j; i++)
        this.constraints.add(new FilterPlan.Constraint(host, cons.getJSONObject(i)));
    }
  }

  // this should go in Constraint, however
  // "static declarations are not allowed in inner classes" :(
  enum ConstraintKind {
    EQ,
    NEQ,
    IN,
    NIN,
    CONTAINS
  };

  static class Constraint {
    private Host host;
    public ConstraintKind kind;
    public String field;
    public ConstraintValue value;

    public Constraint(Host host, ConstraintKind kind, String field, ConstraintValue value) {
      this.kind = kind;
      this.field = field;
      this.value = value;
    }

    public Constraint(Host host, JSONObject json) {
      this.kind = parseConstraintKind(json.getString("kind"));
      this.field = json.optString("field", null);
      JSONObject val = json.getJSONObject("value");
      this.value = parseConstraintValue(host, json.getJSONObject("value"));
    }

    public void ground(Map<Integer, List<Object>> setResults) throws Exceptions.DataFilteringError {
      if (this.value instanceof Ref) {
        Ref ref = (Ref) this.value;
        List<Object> val = new ArrayList(setResults.get(new Integer(ref.resultId)));
        if (ref.field != null)
          for (int i = 0, j = val.size(); i < j; i++)
            try {
              Object v = val.get(i);
              val.set(i, v.getClass().getField(ref.field).get(v));
            } catch (NoSuchFieldException | IllegalAccessException e) {
              throw new Exceptions.DataFilteringError(
                  "Couldn't read field "
                      + ref.field
                      + " of "
                      + String.valueOf(val.get(i)));
            }
        this.value = new Term(val);
      }
    }

    public boolean check(Object obj) {
      Object val;
      String fld = null;
      Class<?> cls = obj.getClass();

      try {
        if (value instanceof Field) {
          fld = ((Field) value).field;
          val = cls.getField(fld).get(obj);
        } else {
          val = ((Term) value).value;
        }
        fld = field;

        if (fld != null) obj = cls.getField(fld).get(obj);
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new Exceptions.DataFilteringError(
            "Error reading field `" + fld + "` from " + cls.toString());
      }

      switch (kind) {
        case EQ:
          return val.equals(obj);
        case NEQ:
          return !val.equals(obj);
        case IN:
          return ((List<Object>) val).indexOf(obj) > -1;
        case NIN:
          return ((List<Object>) val).indexOf(obj) == -1;
        case CONTAINS:
          return ((List<Object>) obj).indexOf(val) > -1;
        default:
          throw new Exceptions.DataFilteringError("Unimplemented");
      }
    }

    private ConstraintKind parseConstraintKind(String kind) throws Exceptions.OsoException {
      if (kind.equals("Eq")) return FilterPlan.ConstraintKind.EQ;
      if (kind.equals("Neq")) return FilterPlan.ConstraintKind.NEQ;
      if (kind.equals("In")) return FilterPlan.ConstraintKind.IN;
      if (kind.equals("Nin")) return FilterPlan.ConstraintKind.NIN;
      if (kind.equals("Contains")) return FilterPlan.ConstraintKind.CONTAINS;
      throw new Exceptions.DataFilteringError("Invalid constraint kind: " + kind);
    }

    private ConstraintValue parseConstraintValue(Host host, JSONObject value)
        throws Exceptions.OsoException {
      String key = value.keys().next();
      if (key.equals("Ref")) return new Ref(value.getJSONObject(key));
      if (key.equals("Term")) return new Term(host.toJava(value.getJSONObject(key)));
      if (key.equals("Field")) return new Field(value);
      throw new Exceptions.DataFilteringError("Invalid constraint value type: " + key);
    }
  }

  abstract static class ConstraintValue {}

  static class Ref extends ConstraintValue {
    public int resultId;
    public String field;

    public Ref(JSONObject json) {
      this.resultId = json.getInt("result_id");
      this.field = json.isNull("field") ? null : json.getString("field");
    }
  }

  static class Field extends ConstraintValue {
    public String field;

    public Field(JSONObject json) {
      this.field = json.getString("Field");
    }
  }

  static class Term extends ConstraintValue {
    public Object value;

    public Term(Object value) {
      this.value = value;
    }
  }
}
