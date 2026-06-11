<script lang="ts">
	// Minimal layout for unauthenticated public surfaces. Does not
	// touch the auth store, render the app sidebar, or check for a
	// session. Pages under this group must be safe to serve to
	// anonymous traffic.
	let { children } = $props();
</script>

{@render children?.()}
