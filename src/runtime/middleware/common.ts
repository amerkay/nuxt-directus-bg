import {
  defineNuxtRouteMiddleware,
  useRuntimeConfig,
  navigateTo,
  useDirectusStorage,
} from "#imports";

export default defineNuxtRouteMiddleware((to, from) => {
  const config = useRuntimeConfig().public.directus;

  if (
    to.path === config.auth.redirect.login ||
    to.path === config.auth.redirect.callback
  ) {
    const { accessToken } = useDirectusStorage();

    if (accessToken.get()) {
      const returnToPath = from.query.redirect?.toString();
      const redirectTo = returnToPath || config.auth.redirect.home;
      return navigateTo(redirectTo);
    }
  }
});
