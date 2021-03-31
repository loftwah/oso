import { inspect } from 'util';
// import 'reflect-metadata';
// import { createConnection } from 'typeorm';
// import {
//   createQueryBuilder,
//   getMetadataArgsStorage,
//   EntityMetadata,
// } from 'typeorm';
import { Oso, Variable } from 'oso';
import type { Class } from 'oso';
import type { Connection } from 'typeorm';

export { Oso };

export async function authorizeModel<T>(
  oso: Oso,
  actor: unknown,
  action: unknown,
  model: Class<T>,
  conn: Connection
): Promise<T[]> {
  // TODO(gj): if T isn't a Class, throw an error? would it make sense to pass
  // a non-class? TypeORM seems to support strings in addition to Entities.

  // TODO(gj): add `bindings` param to query/queryRule & underlying Bind API

  // TODO(gj): add TypeConstraint

  const resource = new Variable('resource');
  const results = oso.queryRule('allow', { args: [actor, action, resource] });
  const expressions = [];

  for await (const result of results) {
    const expr = result.get('resource');
    console.log(inspect(expr, { depth: null }));
    expressions.push(expr);
  }

  console.log('expressions', expressions);

  // TODO(gj): need to name connection?
  return conn.getRepository(model).createQueryBuilder().getMany();

  // filter = None
  // for result in results:
  //     resource_partial = result["bindings"]["resource"]
  //     if filter is None:
  //         filter = Q()
  //
  //     next_filter = partial_to_query_filter(resource_partial, model)
  //     if next_filter == TRUE_FILTER:
  //         return TRUE_FILTER
  //
  //     filter |= next_filter
  //
  // if filter is None:
  //     raise PermissionDenied()
  //
  // return filter
}

// const oso = new Oso();
// const x = oso.__host().toPolar(new Variable('resource'));
// console.log(x);

// TODO(gj): create an Oso() decorator that adds an `.authorized(oso, actor, action)` method?
