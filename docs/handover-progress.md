# Ev Bus Support App Handover And Progress

Last updated: 2026-06-25

This document is the single handover source for the current Ev Bus support app. It combines product intent, engineering principles, implemented work, partial work, known gaps, and the next recommended build order.

## Product Goal

Build a branded Ev Bus support app that feels like WhatsApp, but gives the business control, accountability, routing, notifications, and auditability.

The product is not a ticket system. Customers should see one human support conversation with Ev Bus. Agents and Super Admins should see enough operational structure to prevent missed messages, abandoned customers, and untraceable decisions.

## Core Principles

- Conversation first: one persistent customer support thread, not visible tickets.
- Mobile first: fast on Android browsers, low data use, compact screens, no heavy landing/app shell.
- Efficient by default: small direct code, low query count, indexed hot paths, no dependencies or helpers unless they clearly pay for themselves.
- Durable business actions: messages, approvals, suspensions, closures, assignments, and notifications must be persisted before success is shown.
- Backend-enforced permissions: roles and ownership are checked server-side on every customer-data read and write.
- No fake success: failures must be surfaced, logged, queued, retried, or made visible to admins.
- Cheap reliable stack: Cloudflare Workers/Pages, Durable Objects for realtime, TiDB for durable data, TiDB-backed jobs first, R2 later for private files.
- Configurable operations: branding, departments, limits, assignment capacity, and notification settings should become admin-editable runtime settings.
- Security by default: hashed passwords, rate limits, httpOnly cookies, truncated IP prefixes, audit logs, private file access when uploads arrive.
- Keep V1 focused: finish signup, approval, chat, assignment, notification, close/reopen, audit, settings, and polish before expanding into V2 features.

## Current Stack

- Monorepo: pnpm workspace.
- Frontend: Vite + React SPA/PWA.
- Styling: Tailwind/shadcn-inspired local UI components.
- Backend: Cloudflare Worker API.
- Realtime: Cloudflare Durable Object WebSocket room.
- Database: TiDB Cloud via `@tidbcloud/serverless`.
- Shared contracts: Zod schemas in `packages/shared`.
- Database schema: Drizzle table definitions in `packages/db`.
- Notification queue: TiDB-backed `notification_jobs`.
- Local app URL: `http://localhost:5173/`.
- Local API default: `http://127.0.0.1:8787`.

## Important Repo Areas

- `apps/web/src/App.tsx`: main app state, role routing, data loading, chat orchestration.
- `apps/web/src/LandingPage.tsx`: public home page.
- `apps/web/src/AuthPage.tsx`: login, signup, password reset forms.
- `apps/web/src/layouts/AppLayout.tsx`: logged-in shell with sidebar/header.
- `apps/web/src/pages/ConversationsPage.tsx`: customer, agent, and admin conversation workspace.
- `apps/web/src/pages/ApprovalsPage.tsx`: pending customer approval.
- `apps/web/src/pages/PeoplePages.tsx`: agent/customer management.
- `apps/web/src/pages/NotificationsPage.tsx`: notification job list and manual processing.
- `apps/web/src/pages/SettingsPage.tsx`: basic runtime settings.
- `apps/api/src/auth.ts`: registration, login, logout, password reset, bootstrap/dev migrate.
- `apps/api/src/admin.ts`: approvals, user management, notification admin operations.
- `apps/api/src/conversations.ts`: conversations, messages, assignment, close/reopen, realtime entry.
- `apps/api/src/notifications.ts`: notification queue, merge/debounce, job processing, email message building.
- `apps/api/src/settings.ts`: public and admin settings.
- `packages/db/src/schema.ts`: current database tables and indexes.
- `packages/db/src/migrations.ts`: idempotent development migration runner.
- `packages/shared/src/schemas.ts`: request/response validation contracts.

## What Is Implemented

### Public And Auth

- Public landing page exists.
- Single auth page handles login, signup, password reset request, and reset token submission.
- Signup validates name, email, Ghana phone number, and strong password through shared Zod contracts.
- Pending customers see a pending account state.
- Login and logout work.
- Password reset token flow exists.
- Login attempts are rate-limited by account and IP-derived identifier.
- Sessions are stored server-side using hashed tokens and httpOnly cookies.

### Roles And Permissions

- Roles exist: `customer`, `agent`, `super_admin`.
- Account statuses exist: `pending`, `approved`, `rejected`, `suspended`.
- Super Admin can access admin operations.
- Customer cannot access admin customer/conversation lists.
- Agent cannot access Super Admin-only pages like agents/customers/settings/notification processing.
- Agent can access assigned conversation dashboard.
- Customer can only access their own conversation.
- Suspended users cannot keep active sessions after suspension.
- Users can list active sessions.
- Users can log out everywhere.
- Users can update their message email notification preference.

### Super Admin Operations

- Super Admin can view pending customers.
- Super Admin can approve customers.
- Super Admin can reject customers with a reason at API level.
- Super Admin can create agent accounts.
- Super Admin can suspend agents and customers.
- Super Admin can view agents and customers.
- Super Admin can manually reassign a conversation or unassign it.
- Super Admin can view notification jobs.
- Super Admin can manually process notification jobs.
- Super Admin can update basic settings.
- Super Admin can query audit logs.
- Super Admin can query an operational health summary covering database latency, conversation counts, and notification job counts.

### Conversations And Messages

- Each customer gets one persistent conversation.
- Customers can send text messages.
- Agents and Super Admins can send text messages.
- Messages are persisted before realtime broadcast.
- WebSocket realtime exists for `message.created`.
- Message cache exists on the frontend so reopening an already-loaded chat is faster.
- Stale async chat responses are guarded by selected conversation refs.
- Conversation close with note exists.
- Customer reopen is now allowed and verified at API level.
- Full conversation history remains after close/reopen.
- Admin/agent conversation list loads from the backend.

### Recent Conversation State Improvements

The latest backend work added real conversation state fields:

- `last_customer_message_at`
- `last_agent_message_at`
- `customer_unread_count`
- `agent_unread_count`
- `conversations_waiting_idx` on status and last-message participant timestamps

These were added to:

- Drizzle schema.
- Migration runner.
- Shared conversation response schema.
- Admin conversation list query.
- Message creation updates.
- Message-read clearing.

The admin conversation list now sorts waiting customers first. A waiting conversation means:

- conversation is open
- customer has sent a message
- customer message is newer than the latest agent/admin message, or no agent/admin reply exists

Repeated chat opens avoid unnecessary unread-clearing database writes when the count is already zero.

### UI For Recent Conversation State

Partial UI exists:

- Agent/admin conversation rows show `agentUnreadCount` as a small badge.
- Conversation rows show assigned/unassigned state.
- Conversation rows show closed state.
- Conversation rows show waiting age when the customer is waiting.
- Conversation rows show last activity age otherwise.

Not fully built yet:

- No full SLA/waiting dashboard.
- No filters for waiting, unassigned, mine, closed, or unread.
- No customer-side unread badge.
- No read-receipt visuals in the chat bubbles.
- No admin analytics cards for wait time, open workload, overdue conversations, or assignment health.

### Smart Assignment

Implemented:

- New conversations start unassigned.
- First customer message assigns an unassigned conversation.
- Assignment picks an approved agent with the fewest active open conversations.
- Assignment respects configured max active conversations per agent.
- If no regular agent is available under capacity, assignment falls back to the least-loaded approved Super Admin.
- Automatic assignment and queued-assignment decisions are audit logged.
- Manual Super Admin reassignment exists.
- Agent suspension attempts reassignment using the same basic chooser.

Not fully implemented:

- Online/away presence is not used.
- Department/subsidiary routing is not used.
- Super Admin escalation is basic fallback behavior, not a full threshold/availability model.
- Queueing when nobody is available is represented by `assignedAgentId = null`, but there is no queue-management UI yet.
- Assignment audit/detail UI is missing.

### Notifications

Implemented:

- `notification_jobs` table.
- Notification enqueue helper.
- Dedupe key support.
- Debounced/merged message notification jobs.
- Immediate-style jobs for approval/rejection/password reset/close messages exist as queue entries.
- Manual notification processing endpoint exists.
- Scheduled Worker trigger processes a small batch.
- Dry-run processing exists for acceptance checks.
- Notification job page shows queued/failed/sent summaries.
- Message email notification preference is stored per user.
- Normal message email notifications are skipped if the recipient disables them.
- Transactional notifications such as password reset and account review are not blocked by that preference.

Not fully implemented:

- Production email provider credentials and delivery need final setup.
- Brevo primary provider and Gmail/SMTP fallback need full production verification.
- Push notifications are not implemented.
- Notification preferences have backend support but no dedicated UI yet.
- Health/alerting around notification failures is not implemented.
- Notification details UI is thin.

### Settings

Implemented settings:

- site name
- company name
- tagline
- support email
- subsidiaries list
- departments list
- max active conversations per agent
- email notification debounce minutes

Important limitation:

- Subsidiaries and departments currently exist as settings/display labels. They are not yet full routing entities and are not assigned to agents/customers.

### UI And Layout

Implemented:

- Public home page.
- Compact auth page.
- Main logged-in app layout with sidebar/header.
- Conversations workspace.
- Approvals page.
- Agents page.
- Customers page.
- Notifications page.
- Settings page.
- Compact summary cards were added to approvals, people, and notifications.
- Mobile and desktop layout have been iterated several times.

Still needs polish:

- Pages are functional but not yet launch-quality across every workflow.
- Empty states need richer, business-specific actions.
- Admin pages need more dense operational context.
- Conversation page needs better WhatsApp-like polish: timestamps, grouping, status, read states, input ergonomics, attachment affordances later.
- Sidebar/session card needs final visual polish and overflow checks.
- Customer experience needs its own deliberately designed view instead of sharing too much admin workspace shape.

### Audit Logs

Implemented:

- `audit_logs` table.
- Important backend actions call audit logging in existing flows.
- Super Admin audit-log API exists with basic filters for action, actor, target type, target id, and limit.
- Audit log indexes exist for actor, action, target, and created time.

Missing:

- Audit log UI page.
- Search/filter by actor, action, target, date.
- Export or incident review view.
- More complete audit coverage for every sensitive action.

### Database

Current tables:

- `users`
- `sessions`
- `password_reset_tokens`
- `auth_rate_limits`
- `audit_logs`
- `conversations`
- `messages`
- `settings`
- `notification_jobs`

Useful indexes already present:

- user email uniqueness
- session token and user lookups
- password reset token lookup
- auth rate limit scope/identifier and locked-until lookup
- audit actor lookup
- audit action lookup
- audit target lookup
- audit created-time lookup
- conversation customer uniqueness
- conversation assigned-agent lookup
- conversation status/last-message lookup
- conversation waiting-state lookup
- message conversation/created lookup
- notification status/next-attempt lookup
- notification recipient lookup
- notification dedupe uniqueness

Not yet present:

- files
- message attachments
- reports
- departments as tables
- agent department assignments
- announcements
- announcement reactions/comments
- user notification preferences
- read receipt table or per-message read state
- presence/session activity table

## Backend Features With No Or Partial UI

These are the main things already partly in backend/data but not fully surfaced in UI:

- `lastCustomerMessageAt`: only row waiting age uses it.
- `lastAgentMessageAt`: only row waiting calculation uses it.
- `customerUnreadCount`: backend updates it, but customer UI does not visibly use it.
- `agentUnreadCount`: backend updates it and admin/agent list shows a badge.
- Waiting-first sorting: backend does it, but UI has no filter/SLA dashboard yet.
- Audit logs: backend query API exists, no audit page.
- Admin health: backend summary exists, no dashboard page.
- Active sessions: backend list/logout-all exists, no UI page.
- Notification preferences: backend get/update exists, no UI controls yet.
- Notification jobs: queue/processing/details exist, UI is basic and provider status is not rich.
- Rejection reason: API accepts a reason, UI currently uses a fixed reason.
- Settings for subsidiaries/departments: UI can edit strings, but no routing/assignment UI.
- Max active conversations per agent: backend assignment respects it, but the UI does not explain capacity/queue decisions yet.
- Reassignment: UI supports manual reassignment, but no history/details surface.
- Close/reopen: works, but UI copy and timeline display need polish.

## Verification Already Performed

Recent passing checks:

- `corepack pnpm typecheck`
- `corepack pnpm test`
- `corepack pnpm --filter @evbus/web build`
- `corepack pnpm acceptance`

Recent acceptance coverage includes:

- health
- settings
- anonymous auth denied
- anonymous admin denied
- customer registration
- duplicate registration
- pending customer login denied
- password reset request
- Super Admin login
- Super Admin approval
- agent creation
- customer role boundaries
- agent role boundaries
- agent notification processing denied
- notification dry run
- session listing
- notification preferences
- first message assignment
- admin health
- audit logs
- web shell

Additional manual/API verification:

- Customer can reopen a closed conversation after the latest fix.
- Chat message caching improves revisit speed.
- Local migration endpoint successfully applied the recent conversation columns/index.
- Local migration endpoint successfully applied the user notification preference column and audit indexes.

## Current Git State Notes

Latest pushed commit at handover time:

- `5625b71 Improve conversation waiting state`

There were untracked local files observed:

- `agents.md`
- `recent.txt`

Do not delete or alter untracked/user files unless the user explicitly approves it.

## Local Development Commands

Install:

```sh
corepack pnpm install
```

Run frontend:

```sh
corepack pnpm dev:web
```

Run API:

```sh
corepack pnpm dev:api
```

Run migration after API starts:

```sh
Invoke-WebRequest -Uri http://127.0.0.1:8787/dev/migrate -Method POST
```

Verify:

```sh
corepack pnpm typecheck
corepack pnpm test
corepack pnpm --filter @evbus/web build
corepack pnpm acceptance
```

The acceptance script creates fresh approved test users with generated emails. Passwords are:

- Super Admin password: `Safe-admin-password-123`
- Agent/customer password: `Safe-password-123`

To find the latest local test emails, query approved users ordered by `updated_at DESC`.

## V1 Remaining Work

### Highest Priority

1. Finish conversation workspace quality.
   - Better message grouping.
   - Proper timestamps.
   - Read/unread indicators.
   - Waiting/unassigned/closed filters.
   - Strong selected conversation details.
   - Better empty states.
   - Customer-specific chat view polish.

2. Finish notification delivery.
   - Configure production email provider.
   - Add fallback provider.
   - Verify password reset and approval emails deliver immediately.
   - Verify debounced offline message emails.
   - Add visible admin failure status and retry details.

3. Finish role-specific page completeness.
   - Customer view should be simple, warm, and focused.
   - Agent view should show assigned workload and waiting customers.
   - Super Admin view should show approvals, operations, notifications, and audit visibility.

4. Add audit log UI.
   - Show who did what, when, and target details.
   - Filter by action, actor, target, and date.
   - Include approvals, rejections, suspensions, closures, reopens, assignment changes, settings updates, notification processing.

5. Build UI for backend-complete account/admin surfaces.
   - Active sessions and log out everywhere.
   - Email notification preference.
   - Admin health summary.
   - Audit log page.
   - Rich notification job details and retry status.

6. Harden assignment beyond V1 fallback.
   - Add online/away foundation or mark it explicitly deferred.
   - Add full threshold-based Super Admin escalation if required.
   - Add department/subsidiary routing.
   - Add visible assignment reason/status.

### Important Before Launch

- Add UI for customer notification preferences.
- Add UI for active sessions and "log out everywhere."
- Add richer settings validation/UI.
- Add dashboard health panel for DB/API/notification status.
- Add better handling for server/realtime reconnect states.
- Add pagination/cursor loading for old messages.
- Add optimistic send with failure reconciliation.
- Add better loading skeletons and network failure states.
- Add production deployment notes and environment checklist.
- Add privacy/legal text placeholders.
- Add accessibility review: keyboard, focus, labels, contrast, mobile tap targets.
- Add more tests for close/reopen, unread clearing, waiting sort, assignment, suspension reassignment, notification debounce, and permissions.

## V2 Or Post-V1 Work

- File/photo/document uploads.
- R2 private storage.
- File MIME/content sniffing.
- Image EXIF/location stripping.
- File deduplication.
- Signed expiring file access.
- Customer upload permission toggle.
- Registration note/report handoff.
- Customer reports queue.
- Departments as database entities.
- Agent-department assignments.
- Advanced department/subsidiary routing.
- Agent presence and typing indicators.
- Read receipts.
- Message reactions.
- Reply-to-message quoting.
- Customer message deletion window.
- Agent team group chat.
- Agent private direct messages.
- Announcements.
- Announcement comments/votes/reactions.
- Public homepage announcement banners.
- Push notifications.
- Full health dashboard.
- Advanced analytics and load metrics.
- Backup/recovery plan and production runbooks.

## Recommended Next Build Order

1. Conversation UI completion.
   - This is the highest customer/agent value and uses the backend state that now exists.

2. Notification delivery hardening.
   - The app is only useful if customers know when replies arrive.

3. Audit log UI.
   - Required for business disputes and admin confidence.

4. Admin/account backend UI wiring.
   - Sessions, preferences, admin health, and notification details now have backend support.

5. Assignment hardening.
   - Make workload distribution visible and reliable.

6. Settings/admin polish.
   - Make operational controls clear without adding unnecessary complexity.

7. Production deployment checklist.
   - Secrets, provider config, domain, Cloudflare routes, migrations, backup, and monitoring.

## Known Risks

- Notification delivery is not yet production-proven.
- Realtime exists but does not yet cover typing, presence, read receipts, assignment updates, or settings updates.
- Shared conversation UI risks becoming too admin-shaped for customers unless customer view is polished separately.
- Departments/subsidiaries can mislead users if they look operational before routing actually uses them.
- Acceptance tests are good for the spine but not enough for launch; they need more business regressions.
- Migration runner is intentionally simple and idempotent for development; production migrations need a more controlled process before real customers.

## Definition Of V1 Complete

V1 should only be called complete when these are true:

- Customer can sign up, wait, get approved, log in, chat, receive notifications, and reopen closed conversations.
- Agent can log in, see assigned/waiting conversations, reply quickly, close with a note, and trust the list order.
- Super Admin can approve/reject, create/suspend users, reassign conversations, process/inspect notifications, edit core settings, and review audit logs.
- Notifications are reliable enough for real customers.
- Role boundaries are tested and enforced in the backend.
- Chat load feels fast on repeat opens and slow networks.
- UI is compact, polished, and not empty on core pages.
- Critical checks pass: typecheck, tests, web build, acceptance, and focused manual browser QA.
