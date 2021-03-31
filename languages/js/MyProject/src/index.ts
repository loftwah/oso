import 'reflect-metadata';
import { createConnection } from 'typeorm';
import { authorizeModel, Oso } from 'typeorm-oso';

import { User } from './entity/User';
import { Post } from './entity/Post';

async function seed(connection) {
  let alice: User;
  try {
    alice = await connection.manager.findOneOrFail(User, 1);
  } catch {
    alice = new User();
    alice.email = 'alice@example.com';

    const posts = [1, 2, 3].map((n) => {
      const post = new Post();
      post.title = `Title of Post ${n}`;
      post.contents = `Contents of Post ${n}.`;
      return post;
    });
    alice.posts = posts;

    await connection.manager.save(alice);
    await Promise.all(posts.map((p) => connection.manager.save(p)));
  }
  return alice;
}

async function main() {
  const connection = await createConnection();

  try {
    const alice = await seed(connection);
    await run(connection, alice);
  } finally {
    await connection.dropDatabase();
    await connection.close();
  }
}

main();

async function run(connection, alice) {
  const oso = new Oso();

  oso.registerClass(User);
  oso.registerClass(Post);
  await oso.loadStr(`
    allow(u: User, "read", p) if
        p.author = u;
`);

  const posts = await authorizeModel(oso, alice, 'read', Post, connection);
  // console.log('posts', posts);
}
