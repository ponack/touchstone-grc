<script lang="ts">
	import { goto } from '$app/navigation';
	import { createConnector, type ConnectorKind } from '$lib/api/connectors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	let kind = $state<ConnectorKind>('aws');
	let name = $state('');
	let scheduleCron = $state('');
	let submitting = $state(false);

	// ── AWS ───────────────────────────────────────────────────────────
	let awsAccountId = $state('');
	let awsRegions = $state('us-east-1');
	let awsAuthMethod = $state<'role' | 'key'>('role');
	let awsRoleArn = $state('');
	let awsExternalId = $state('');
	let awsAccessKeyId = $state('');
	let awsSecretAccessKey = $state('');

	// ── Azure ─────────────────────────────────────────────────────────
	let azTenantId = $state('');
	let azSubscriptionId = $state('');
	let azClientId = $state('');
	let azClientSecret = $state('');

	// ── GitHub ────────────────────────────────────────────────────────
	let ghOrg = $state('');
	let ghAccessToken = $state('');

	// ── Linear ────────────────────────────────────────────────────────
	let linWorkspaceName = $state('');
	let linIncidentLabels = $state('security, incident');
	let linSlaWindowDays = $state(30);
	let linAttestNoIncidents = $state(false);
	let linApiKey = $state('');

	// ── Jira ──────────────────────────────────────────────────────────
	let jiraSiteUrl = $state('');
	let jiraEmail = $state('');
	let jiraProjectKeys = $state('');
	let jiraIncidentLabels = $state('security, incident');
	let jiraSlaWindowDays = $state(30);
	let jiraAttestNoIncidents = $state(false);
	let jiraApiToken = $state('');

	// ── GCP ───────────────────────────────────────────────────────────
	let gcpProjectId = $state('');
	let gcpWorkspaceCustomerId = $state('');
	let gcpWorkspaceAdminEmail = $state('');
	let gcpServiceAccountKeyJson = $state('');

	function buildConfig(): Record<string, unknown> {
		if (kind === 'aws') {
			const cfg: Record<string, unknown> = {
				account_id: awsAccountId.trim(),
				regions: awsRegions
					.split(',')
					.map((r) => r.trim())
					.filter((r) => r.length > 0),
				auth_method: awsAuthMethod
			};
			if (awsAuthMethod === 'role') {
				cfg.role_arn = awsRoleArn.trim();
				if (awsExternalId.trim()) cfg.external_id = awsExternalId.trim();
			} else {
				cfg.access_key_id = awsAccessKeyId.trim();
				cfg.secret_access_key = awsSecretAccessKey;
			}
			return cfg;
		}
		if (kind === 'azure') {
			const cfg: Record<string, unknown> = {
				tenant_id: azTenantId.trim(),
				client_id: azClientId.trim(),
				client_secret: azClientSecret
			};
			if (azSubscriptionId.trim()) cfg.subscription_id = azSubscriptionId.trim();
			return cfg;
		}
		if (kind === 'github') {
			return {
				org: ghOrg.trim(),
				access_token: ghAccessToken
			};
		}
		if (kind === 'linear') {
			return {
				workspace_name: linWorkspaceName.trim(),
				incident_labels: linIncidentLabels
					.split(',')
					.map((s) => s.trim())
					.filter((s) => s.length > 0),
				sla_window_days: linSlaWindowDays,
				attest_no_incidents: linAttestNoIncidents,
				api_key: linApiKey
			};
		}
		if (kind === 'jira') {
			const jiraCfg: Record<string, unknown> = {
				site_url: jiraSiteUrl.trim(),
				email: jiraEmail.trim(),
				incident_labels: jiraIncidentLabels
					.split(',')
					.map((s) => s.trim())
					.filter((s) => s.length > 0),
				sla_window_days: jiraSlaWindowDays,
				attest_no_incidents: jiraAttestNoIncidents,
				api_token: jiraApiToken
			};
			const projectKeys = jiraProjectKeys
				.split(',')
				.map((s) => s.trim())
				.filter((s) => s.length > 0);
			if (projectKeys.length > 0) jiraCfg.project_keys = projectKeys;
			return jiraCfg;
		}
		// gcp
		const gcpCfg: Record<string, unknown> = {
			project_id: gcpProjectId.trim(),
			service_account_key_json: gcpServiceAccountKeyJson
		};
		const customer = gcpWorkspaceCustomerId.trim();
		const admin = gcpWorkspaceAdminEmail.trim();
		if (customer) gcpCfg.workspace_customer_id = customer;
		if (admin) gcpCfg.workspace_admin_email = admin;
		return gcpCfg;
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		submitting = true;
		try {
			const created = await createConnector({
				kind,
				name: name.trim(),
				config: buildConfig(),
				schedule_cron: scheduleCron.trim() || null
			});
			toasts.success(`Created ${created.name}.`);
			await goto(`/connectors/${created.id}`);
		} catch (err) {
			toasts.error((err as Error).message);
		} finally {
			submitting = false;
		}
	}

	const kinds: { value: ConnectorKind; label: string; blurb: string }[] = [
		{
			value: 'aws',
			label: 'AWS',
			blurb: 'Read-only IAM credentials. Role assumption recommended.'
		},
		{
			value: 'azure',
			label: 'Azure',
			blurb: 'Service Principal (tenant + client ID + client secret).'
		},
		{
			value: 'github',
			label: 'GitHub',
			blurb: 'Organization + Personal Access Token (read:org scope).'
		},
		{
			value: 'linear',
			label: 'Linear',
			blurb: 'Workspace + Personal API Key. Tracks incident-labelled tickets for CC7.4.'
		},
		{
			value: 'jira',
			label: 'Jira',
			blurb: 'Atlassian Cloud site + email + API token. Parallel CC7.4 source to Linear.'
		},
		{
			value: 'gcp',
			label: 'GCP',
			blurb: 'Service account JSON. Optional Workspace customer for CC6.1 2SV evidence.'
		}
	];
</script>

<svelte:head>
	<title>New connector · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/connectors" class="text-sm text-zinc-500 underline-offset-4 hover:underline"
		>← Connectors</a
	>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">New connector</h1>

	<form onsubmit={submit} class="mt-8 space-y-5">
		<fieldset class="space-y-2 rounded-md border border-zinc-800 p-4">
			<legend class="px-1 text-sm font-medium text-zinc-300">Kind</legend>
			{#each kinds as k (k.value)}
				<label class="flex items-start gap-2">
					<input type="radio" name="kind" value={k.value} bind:group={kind} />
					<span>
						<span class="block text-sm text-zinc-100">{k.label}</span>
						<span class="block text-xs text-zinc-500">{k.blurb}</span>
					</span>
				</label>
			{/each}
		</fieldset>

		<div>
			<label for="name" class="mb-1 block text-sm text-zinc-300">Name</label>
			<input
				id="name"
				type="text"
				required
				placeholder={kind === 'aws' ? 'Production AWS' : 'Production Azure'}
				bind:value={name}
				class="field-input"
			/>
		</div>

		{#if kind === 'aws'}
			<div>
				<label for="account_id" class="mb-1 block text-sm text-zinc-300">AWS account ID</label>
				<input
					id="account_id"
					type="text"
					required
					inputmode="numeric"
					pattern="[0-9]{'{'}12{'}'}"
					placeholder="123456789012"
					bind:value={awsAccountId}
					class="field-input"
				/>
			</div>

			<div>
				<label for="regions" class="mb-1 block text-sm text-zinc-300">
					Regions <span class="text-xs text-zinc-500">(comma-separated)</span>
				</label>
				<input id="regions" type="text" required bind:value={awsRegions} class="field-input" />
			</div>

			<fieldset class="space-y-3 rounded-md border border-zinc-800 p-4">
				<legend class="px-1 text-sm font-medium text-zinc-300">Authentication</legend>
				<label class="flex items-start gap-2">
					<input type="radio" name="auth_method" value="role" bind:group={awsAuthMethod} />
					<span>
						<span class="block text-sm text-zinc-100">Role assumption (recommended)</span>
						<span class="block text-xs text-zinc-500">
							Worker uses ambient credentials to <code>sts:AssumeRole</code> into your role.
						</span>
					</span>
				</label>
				<label class="flex items-start gap-2">
					<input type="radio" name="auth_method" value="key" bind:group={awsAuthMethod} />
					<span>
						<span class="block text-sm text-zinc-100">Access key + secret</span>
						<span class="block text-xs text-zinc-500">
							Long-lived IAM key. Encrypted at rest with TOUCHSTONE_SECRET_KEY.
						</span>
					</span>
				</label>
			</fieldset>

			{#if awsAuthMethod === 'role'}
				<div>
					<label for="role_arn" class="mb-1 block text-sm text-zinc-300">Role ARN</label>
					<input
						id="role_arn"
						type="text"
						required
						placeholder="arn:aws:iam::123456789012:role/TouchstoneReadOnly"
						bind:value={awsRoleArn}
						class="field-input"
					/>
				</div>
				<div>
					<label for="external_id" class="mb-1 block text-sm text-zinc-300">
						External ID <span class="text-xs text-zinc-500">(optional)</span>
					</label>
					<input id="external_id" type="text" bind:value={awsExternalId} class="field-input" />
				</div>
			{:else}
				<div>
					<label for="access_key_id" class="mb-1 block text-sm text-zinc-300">Access key ID</label>
					<input
						id="access_key_id"
						type="text"
						required
						autocomplete="off"
						bind:value={awsAccessKeyId}
						class="field-input"
					/>
				</div>
				<div>
					<label for="secret_access_key" class="mb-1 block text-sm text-zinc-300">
						Secret access key
					</label>
					<input
						id="secret_access_key"
						type="password"
						required
						autocomplete="off"
						bind:value={awsSecretAccessKey}
						class="field-input"
					/>
				</div>
			{/if}
		{:else if kind === 'azure'}
			<div>
				<label for="tenant_id" class="mb-1 block text-sm text-zinc-300">Tenant ID</label>
				<input
					id="tenant_id"
					type="text"
					required
					placeholder="12345678-1234-1234-1234-1234567890ab"
					bind:value={azTenantId}
					class="field-input"
				/>
			</div>

			<div>
				<label for="subscription_id" class="mb-1 block text-sm text-zinc-300">
					Subscription ID
					<span class="text-xs text-zinc-500">
						(optional — required for subscription-scoped services)
					</span>
				</label>
				<input
					id="subscription_id"
					type="text"
					placeholder="00000000-0000-0000-0000-000000000000"
					bind:value={azSubscriptionId}
					class="field-input"
				/>
			</div>

			<div>
				<label for="client_id" class="mb-1 block text-sm text-zinc-300">
					Client ID
					<span class="text-xs text-zinc-500">(Service Principal application ID)</span>
				</label>
				<input
					id="client_id"
					type="text"
					required
					placeholder="abcdef01-2345-6789-abcd-ef0123456789"
					bind:value={azClientId}
					class="field-input"
				/>
			</div>

			<div>
				<label for="client_secret" class="mb-1 block text-sm text-zinc-300">Client secret</label>
				<input
					id="client_secret"
					type="password"
					required
					autocomplete="off"
					bind:value={azClientSecret}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Encrypted at rest with TOUCHSTONE_SECRET_KEY. Required Graph permissions:
					<code>AuditLog.Read.All</code> and <code>UserAuthenticationMethod.Read.All</code>
					(admin-consented application permissions).
				</p>
			</div>
		{:else if kind === 'github'}
			<div>
				<label for="gh_org" class="mb-1 block text-sm text-zinc-300">Organization</label>
				<input
					id="gh_org"
					type="text"
					required
					placeholder="acme-co"
					bind:value={ghOrg}
					class="field-input"
				/>
			</div>

			<div>
				<label for="gh_access_token" class="mb-1 block text-sm text-zinc-300">
					Personal Access Token
				</label>
				<input
					id="gh_access_token"
					type="password"
					required
					autocomplete="off"
					placeholder="ghp_…"
					bind:value={ghAccessToken}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Classic PAT with <code>read:org</code> scope (or a fine-grained token with organization
					members read access). Encrypted at rest with TOUCHSTONE_SECRET_KEY.
				</p>
			</div>
		{:else if kind === 'linear'}
			<div>
				<label for="lin_workspace_name" class="mb-1 block text-sm text-zinc-300">
					Workspace name
				</label>
				<input
					id="lin_workspace_name"
					type="text"
					required
					placeholder="Forged in Feathers"
					bind:value={linWorkspaceName}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Display name only — Linear API keys are workspace-scoped, so one connector covers one
					workspace.
				</p>
			</div>

			<div>
				<label for="lin_incident_labels" class="mb-1 block text-sm text-zinc-300">
					Incident labels <span class="text-xs text-zinc-500">(comma-separated)</span>
				</label>
				<input
					id="lin_incident_labels"
					type="text"
					required
					bind:value={linIncidentLabels}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Ticket labels that mark security incidents. CC7.4 evaluates these.
				</p>
			</div>

			<div>
				<label for="lin_sla_window_days" class="mb-1 block text-sm text-zinc-300">
					SLA window (days)
				</label>
				<input
					id="lin_sla_window_days"
					type="number"
					min="1"
					max="365"
					required
					bind:value={linSlaWindowDays}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Closed-in-window tickets prove the workflow runs; tickets open past this window fail
					CC7.4.
				</p>
			</div>

			<label class="flex items-start gap-2">
				<input type="checkbox" bind:checked={linAttestNoIncidents} class="mt-1" />
				<span>
					<span class="block text-sm text-zinc-100">Attest: no security incidents this window</span>
					<span class="block text-xs text-zinc-500">
						Use only when the window genuinely had zero incidents. Lets CC7.4 pass without any
						closed tickets — but you're on the record.
					</span>
				</span>
			</label>

			<div>
				<label for="lin_api_key" class="mb-1 block text-sm text-zinc-300">
					Personal API key
				</label>
				<input
					id="lin_api_key"
					type="password"
					required
					autocomplete="off"
					placeholder="lin_api_…"
					bind:value={linApiKey}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Create at Linear → Settings → Account → API. Encrypted at rest with
					TOUCHSTONE_SECRET_KEY.
				</p>
			</div>
		{:else if kind === 'jira'}
			<div>
				<label for="jira_site_url" class="mb-1 block text-sm text-zinc-300">Site URL</label>
				<input
					id="jira_site_url"
					type="text"
					required
					placeholder="https://acme.atlassian.net"
					bind:value={jiraSiteUrl}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Atlassian Cloud only. Must end in <code>.atlassian.net</code>.
				</p>
			</div>

			<div>
				<label for="jira_email" class="mb-1 block text-sm text-zinc-300">Atlassian email</label>
				<input
					id="jira_email"
					type="email"
					required
					placeholder="ops@example.com"
					bind:value={jiraEmail}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					The Atlassian account email used to mint the API token (Basic auth pair).
				</p>
			</div>

			<div>
				<label for="jira_project_keys" class="mb-1 block text-sm text-zinc-300">
					Project keys <span class="text-xs text-zinc-500">(comma-separated, optional)</span>
				</label>
				<input
					id="jira_project_keys"
					type="text"
					placeholder="SEC, OPS"
					bind:value={jiraProjectKeys}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Leave empty to search across all projects.
				</p>
			</div>

			<div>
				<label for="jira_incident_labels" class="mb-1 block text-sm text-zinc-300">
					Incident labels <span class="text-xs text-zinc-500">(comma-separated)</span>
				</label>
				<input
					id="jira_incident_labels"
					type="text"
					required
					bind:value={jiraIncidentLabels}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Ticket labels that mark security incidents. CC7.4 evaluates these.
				</p>
			</div>

			<div>
				<label for="jira_sla_window_days" class="mb-1 block text-sm text-zinc-300">
					SLA window (days)
				</label>
				<input
					id="jira_sla_window_days"
					type="number"
					min="1"
					max="365"
					required
					bind:value={jiraSlaWindowDays}
					class="field-input"
				/>
			</div>

			<label class="flex items-start gap-2">
				<input type="checkbox" bind:checked={jiraAttestNoIncidents} class="mt-1" />
				<span>
					<span class="block text-sm text-zinc-100">Attest: no security incidents this window</span>
					<span class="block text-xs text-zinc-500">
						Use only when the window genuinely had zero incidents. Lets CC7.4 pass without any
						closed tickets — but you're on the record.
					</span>
				</span>
			</label>

			<div>
				<label for="jira_api_token" class="mb-1 block text-sm text-zinc-300">API token</label>
				<input
					id="jira_api_token"
					type="password"
					required
					autocomplete="off"
					placeholder="ATATT…"
					bind:value={jiraApiToken}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Create at id.atlassian.com → Security → API tokens. Encrypted at rest with
					TOUCHSTONE_SECRET_KEY.
				</p>
			</div>
		{:else if kind === 'gcp'}
			<div>
				<label for="gcp_project_id" class="mb-1 block text-sm text-zinc-300">Project ID</label>
				<input
					id="gcp_project_id"
					type="text"
					required
					placeholder="acme-prod-001"
					bind:value={gcpProjectId}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					6-30 chars, lowercase, must start with a letter. Project-scoped scanners (Cloud Storage,
					VPC firewall, Cloud Logging, SCC, Cloud SQL) run against this project.
				</p>
			</div>

			<div>
				<label for="gcp_workspace_customer_id" class="mb-1 block text-sm text-zinc-300">
					Workspace customer ID <span class="text-xs text-zinc-500">(optional)</span>
				</label>
				<input
					id="gcp_workspace_customer_id"
					type="text"
					placeholder="my_customer or C01abc234"
					bind:value={gcpWorkspaceCustomerId}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					Set to enable CC6.1 evidence via Admin SDK Directory. Use <code>my_customer</code> for the
					tenant your SA impersonates, or a C-prefixed customer ID.
				</p>
			</div>

			<div>
				<label for="gcp_workspace_admin_email" class="mb-1 block text-sm text-zinc-300">
					Workspace admin email <span class="text-xs text-zinc-500">(required if customer set)</span>
				</label>
				<input
					id="gcp_workspace_admin_email"
					type="email"
					placeholder="admin@example.com"
					bind:value={gcpWorkspaceAdminEmail}
					class="field-input"
				/>
				<p class="mt-1 text-xs text-zinc-500">
					The Workspace admin the service account impersonates via domain-wide delegation.
				</p>
			</div>

			<div>
				<label for="gcp_service_account_key_json" class="mb-1 block text-sm text-zinc-300">
					Service account key (JSON)
				</label>
				<textarea
					id="gcp_service_account_key_json"
					required
					rows="10"
					autocomplete="off"
					placeholder={'{\n  "type": "service_account",\n  ...\n}'}
					bind:value={gcpServiceAccountKeyJson}
					class="field-input font-mono text-xs"
				></textarea>
				<p class="mt-1 text-xs text-zinc-500">
					Paste the entire SA key file contents. Required roles: <code>roles/cloudsql.viewer</code>,
					<code>roles/compute.viewer</code>, <code>roles/storage.legacyBucketReader</code>,
					<code>roles/logging.viewer</code>, <code>roles/securitycenter.findingsViewer</code>
					— project-scoped. Encrypted at rest with TOUCHSTONE_SECRET_KEY.
				</p>
			</div>
		{/if}

		<div>
			<label for="schedule_cron" class="mb-1 block text-sm text-zinc-300">
				Schedule
				<span class="text-xs text-zinc-500">
					(cron, optional — leave empty for on-demand)
				</span>
			</label>
			<input
				id="schedule_cron"
				type="text"
				placeholder="0 6 * * *"
				bind:value={scheduleCron}
				class="field-input"
			/>
		</div>

		<div class="flex items-center gap-3 pt-2">
			<button
				type="submit"
				disabled={submitting}
				class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
				style="background-color: var(--accent);"
			>
				{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
				Create connector
			</button>
			<a href="/connectors" class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</a>
		</div>
	</form>
</div>
