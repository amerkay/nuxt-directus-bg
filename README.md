## Nuxt Directus

[![npm version][npm-version-src]][npm-version-href]
[![npm downloads][npm-downloads-src]][npm-downloads-href]
[![License][license-src]][license-href]
[![Nuxt][nuxt-src]][nuxt-href]

A Nuxt 3 module for integrating the official Directus [JS SDK](https://github.com/directus/directus/tree/main/sdk) into your Nuxt 3 project.

**IMPORTANT**

_This version `2` is based on the new Directus SDK. The version based on the old Directus SDK is `v1` under `version-1` branch._

- ✔️ Typescript first
- ✔️ Lightweight & dependency free
- ✔️ Modular architecture with tree shaking
- ✔️ `fetch` over `axios` for portability
- ✔️ Built-in realtime support

## Todos

- [x] Add a plugin to create a Directus client.
- [x] Provide `$directus` helper to expose Directus client.
- [x] Add authentication composable & page middlewares.
- [x] Handle universal refresh of access token with cookie storage.
- [ ] Add `graphql` composable.
- [ ] Add `realtime` composable.
- [ ] Consider auto import of `@directus/sdk` APIs.
- [x] Consider the usage of `$fetch` over `fetch` for transport.
- [ ] Consider usage of realtime APIs with SSR.

## Installation

Add `@bg-dev/nuxt-directus` dependency to your project

```bash
# Using npm
npm install --save-dev @bg-dev/nuxt-directus

# Using yarn
yarn add --dev @bg-dev/nuxt-directus
```

## Setup

Add `@bg-dev/nuxt-directus` to the `modules` section of `nuxt.config.ts` and set directus options

```js
export default defineNuxtConfig({
  modules: ["@bg-dev/nuxt-directus"],

  directus: {
    baseUrl: "http://127.0.0.1:8055", // Directus app base url
    nuxtBaseUrl: "http://127.0.0.1:3000", // Nuxt app base url
    auth: {
      enableGlobalAuthMiddleware: false, // Enable auth middleware on every page
      refreshTokenCookieName: "directus_refresh_token",
      accessTokenCookieName: "directus_access_token",
      msRefreshBeforeExpires: 3000,
      redirect: {
        login: "/auth/login", // Path to redirect when login is required
        logout: "/auth/login", // Path to redirect after logout
        home: "/home", // Path to redirect after successful login
        resetPassword: "/auth/reset-password", // Path to redirect for password reset
        callback: "/auth/callback", // Path to redirect after login with provider
      },
    },

    graphql: {
      httpEndpoint: "http://127.0.0.1:8055/graphql", // You can pass static `access_token` as query param
      wsEndpoint: "ws://127.0.0.1:8055/graphql",
    },
  },
});
```

That's it! You can now use `@bg-dev/nuxt-directus` in your Nuxt app ✨

## REST

The module has `useDirectusRest` composable for data fetching with REST API. It is a wrapper around Directus SDK `request` API with auto refresh of access token.
For better DX, you can get the types definition of your directus project via [directus-extension-generate-types](https://github.com/maltejur/directus-extension-generate-types). The generated `types.ts` file can be used in your Nuxt project via `global.d.ts` file.

```js
import { CustomDirectusTypes } from "./types";

declare global {
  interface DirectusSchema extends CustomDirectusTypes {}
}
```

## Graphql

**This feature is experimental**

The module uses [nuxt-apollo](https://apollo.nuxtjs.org/) for Graphql data fetching with authorization. Please refer to docs for API usage.
To use graphql subscription, please make sure to set:

- `WEBSOCKETS_ENABLED` env to `true`
- `WEBSOCKETS_GRAPHQL_ENABLED` env to true

### GQL auto-completion

In order to benefit autocomplete suggestion when writing graphql queries, you can install [GraphQL: Language Feature Support](https://marketplace.visualstudio.com/items?itemName=GraphQL.vscode-graphql) vscode extension.
Then create `graphql.config.js` and paste the config object below. In order to introspect graphql schema:

- A static access token for the authenticated role needs to be passed as query parameter.
- `WEBSOCKETS_GRAPHQL_AUTH` env needs to be set to `strict`.
- `GRAPHQL_INTROSPECTION` env set to `true`.

```js
// ~/graphql.config.js
const endpoint = "http://127.0.0.1:8055?access_token=xxx";

module.exports = {
  projects: {
    app: {
      schema: [endpoint],
      documents: [
        "./pages/**/*.vue",
        "./components/**/*.vue",
        "./composables/**/*.ts",
        "./app.vue",
      ],
    },
  },
};
```

### Codegen

In order to benefit automatically typed Queries, Mutations and, Subscriptions, you can install [Graphql Code Generator](https://the-guild.dev/graphql/codegen/docs/guides/react-vue).

```bash
npm i -D @graphql-codegen/cli @graphql-codegen/client-preset @parcel/watcher
```

Then create `codegen.ts` and paste the config object below.

```js
// ~/codegen.ts

const endpoint = "http://127.0.0.1:8055?access_token=xxx";

const config = {
  schema: endpoint,
  documents: [
    "./pages/**/*.vue",
    "./components/**/*.vue",
    "./composables/**/*.ts",
    "./app.vue",
  ],
  ignoreNoDocuments: true,
  generates: {
    "./gql/": {
      preset: "client",
      config: {
        useTypeImports: true,
      },
    },
  },
};

export default config;
```

Finally start GraphQL Code Generator in watch mode, this will type your GraphQL queries as you write them.

```bash
npx graphql-codegen --watch
```

## Usage

For protecting page routes, 2 possible approachs can be used:

- Globally enable and locally disable

```js
enableGlobalAuthMiddleware: true;
```

```js
definePageMeta({ auth: false });
```

- Locally enable

```js
definePageMeta({ middleware: "auth" }); // Redirects to login path when not loggedIn
```

```js
definePageMeta({ middleware: "guest" }); // Redirects to home path when loggedIn
```

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

[MIT License](./LICENSE)

<!-- Badges -->

[npm-version-src]: https://img.shields.io/npm/v/@bg-dev/nuxt-directus/latest.svg?style=flat&colorA=18181B&colorB=28CF8D
[npm-version-href]: https://npmjs.com/package/@bg-dev/nuxt-directus
[npm-downloads-src]: https://img.shields.io/npm/dt/@bg-dev/nuxt-directus.svg?style=flat&colorA=18181B&colorB=28CF8D
[npm-downloads-href]: https://npmjs.com/package/@bg-dev/nuxt-directus
[license-src]: https://img.shields.io/npm/l/@bg-dev/nuxt-directus.svg?style=flat&colorA=18181B&colorB=28CF8D
[license-href]: https://npmjs.com/package/@bg-dev/nuxt-directus
[nuxt-src]: https://img.shields.io/badge/Nuxt-18181B?logo=nuxt.js
[nuxt-href]: https://nuxt.com
