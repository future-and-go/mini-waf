# Code Standards

## Admin panel (web/admin-panel) — refine v5 hook deps

`useCustom()` rebuilds its `result` wrapper object on every render (upstream does
not memoize it). Never put the wrapper in a `useEffect`/`useMemo` dependency
array — it re-fires every render and clobbers in-progress form edits and local
toggle state. Depend on the stable payload instead:

```ts
useEffect(() => { /* hydrate form */ }, [configQuery.result?.data]); // ✅ stable
useEffect(() => { /* hydrate form */ }, [configQuery.result]);       // ❌ re-fires every render
```

`result.data` is referentially stable via react-query structural sharing; the
empty-state fallback is a module constant upstream, so the dep only changes when
the server payload actually changes.
