import { type FormEvent, useMemo, useState } from "react";
import type { Conversation, ConversationSummary, Message, PublicUser } from "@evbus/shared";
import { MoreVertical, RefreshCw, Search, Send } from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";

type ConversationsPageProps = {
  agents: PublicUser[];
  conversations: ConversationSummary[];
  messages: Message[];
  onCloseConversation: (event: FormEvent<HTMLFormElement>) => void;
  onReassign: (event: FormEvent<HTMLFormElement>) => void;
  onRefresh: () => void;
  onReopenConversation: () => void;
  onSelectConversation: (conversationId: string) => void;
  onSendMessage: (event: FormEvent<HTMLFormElement>) => void;
  selectedConversation: Conversation | ConversationSummary | null;
  selectedConversationId: string | null;
  user: PublicUser;
};

export function ConversationsPage({
  agents,
  conversations,
  messages,
  onCloseConversation,
  onReassign,
  onRefresh,
  onReopenConversation,
  onSelectConversation,
  onSendMessage,
  selectedConversation,
  selectedConversationId,
  user
}: ConversationsPageProps) {
  const [query, setQuery] = useState("");
  const showInbox = user.role !== "customer";
  const canClose = user.role !== "customer" && selectedConversation?.status !== "closed";
  const canReassign = user.role === "super_admin" && Boolean(selectedConversation);
  const isClosed = selectedConversation?.status === "closed";
  const filteredConversations = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return conversations;

    return conversations.filter((item) =>
      [item.customerName, item.customerEmail, item.lastMessagePreview ?? ""]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery)
    );
  }, [conversations, query]);

  return (
    <div
      className={
        showInbox
          ? "grid h-full min-h-0 overflow-hidden rounded-md border border-border bg-white shadow-sm md:grid-cols-[300px_minmax(0,1fr)] xl:grid-cols-[320px_minmax(0,1fr)]"
          : "grid h-full min-h-0 overflow-hidden rounded-md border border-border bg-white shadow-sm"
      }
    >
        {showInbox ? (
          <aside className="grid min-h-0 grid-rows-[auto_auto_minmax(0,1fr)] border-b border-border bg-[#f7faf7] md:border-b-0 md:border-r">
            <div className="flex h-12 items-center justify-between border-b border-border px-3">
              <div>
                <h2 className="text-sm font-semibold">Chats</h2>
                <p className="text-xs text-muted-foreground">
                  {filteredConversations.length}
                  {query ? ` of ${conversations.length}` : ""} conversations
                </p>
              </div>
              <Button type="button" variant="ghost" size="icon" onClick={onRefresh} aria-label="Refresh conversations">
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>

            <div className="border-b border-border p-2">
              <div className="flex h-8 items-center gap-2 rounded-md bg-[#eef3ef] px-3 text-sm text-muted-foreground">
                <Search className="h-4 w-4" />
                <input
                  className="min-w-0 flex-1 bg-transparent text-foreground outline-none placeholder:text-muted-foreground"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search customers"
                  aria-label="Search customers"
                />
              </div>
            </div>

            <div className="min-h-0 overflow-auto">
              {filteredConversations.length === 0 ? (
                <p className="m-3 rounded-md border border-dashed border-border bg-background p-3 text-sm text-muted-foreground">
                  {query ? "No conversations match that search." : user.role === "agent" ? "No assigned conversations yet." : "No conversations yet."}
                </p>
              ) : (
                filteredConversations.map((item) => (
                  <button
                    type="button"
                    className="grid w-full gap-0.5 border-b border-border/70 px-3 py-2.5 text-left text-sm transition data-[active=true]:bg-[#e5f3ef] data-[active=false]:hover:bg-white"
                    data-active={item.id === selectedConversationId}
                    key={item.id}
                    onClick={() => onSelectConversation(item.id)}
                  >
                    <span className="flex items-center justify-between gap-2">
                      <strong className="truncate">{item.customerName}</strong>
                      <StatusDot status={item.status} />
                    </span>
                    <span className="truncate text-muted-foreground">
                      {item.lastMessagePreview ?? item.customerEmail}
                    </span>
                  </button>
                ))
              )}
            </div>
          </aside>
        ) : null}

        <section className="grid min-h-0 min-w-0 grid-rows-[52px_minmax(0,1fr)_auto] bg-[#efeae2]">
          <ChatHeader conversation={selectedConversation} isCustomer={user.role === "customer"} />

          <div className="grid min-h-0 content-start gap-1.5 overflow-auto bg-[radial-gradient(circle_at_top_left,rgba(255,255,255,0.38),transparent_26%)] p-3">
            {messages.length === 0 ? (
              <p className="self-center justify-self-center rounded-full bg-white/70 px-4 py-2 text-sm text-muted-foreground">
                No messages yet.
              </p>
            ) : (
              messages.map((item) => (
                <MessageBubble isOwn={item.senderId === user.id} item={item} key={item.id} />
              ))
            )}
          </div>

          <div className="shrink-0 border-t border-border bg-[#f7f3ed] p-2">
            {selectedConversation ? (
              <div className="mb-2 grid gap-2 lg:grid-cols-[minmax(220px,0.7fr)_minmax(260px,1fr)]">
                {isClosed ? (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-1.5 text-sm text-amber-800 lg:col-span-2">
                    <span>This conversation is closed.</span>
                    <Button type="button" variant="outline" size="sm" onClick={onReopenConversation}>
                      Reopen
                    </Button>
                  </div>
                ) : null}

                {canReassign ? (
                  <form className="grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onReassign}>
                    <select
                      name="agentId"
                      className="h-9 min-w-0 rounded-md border border-input bg-background px-3 text-sm"
                      defaultValue={selectedConversation.assignedAgentId ?? ""}
                      aria-label="Assigned agent"
                    >
                      <option value="">Unassigned</option>
                      {agents.map((agent) => (
                        <option value={agent.id} key={agent.id}>
                          {agent.name}
                        </option>
                      ))}
                    </select>
                    <Button type="submit" variant="outline" size="sm">Reassign</Button>
                  </form>
                ) : null}

                {canClose ? (
                  <form className="grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onCloseConversation}>
                    <Input name="note" className="h-9" placeholder="Closing note" required maxLength={1000} />
                    <Button type="submit" size="sm">Close</Button>
                  </form>
                ) : null}
              </div>
            ) : null}

            <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onSendMessage}>
              <Input
                name="body"
                className="h-10 rounded-full bg-white px-4"
                placeholder={isClosed ? "Reopen this conversation before sending" : "Type a message"}
                required
                maxLength={5000}
                disabled={isClosed}
              />
              <Button type="submit" className="h-10 rounded-full px-5" disabled={isClosed}>
                <Send className="h-4 w-4" />
                Send
              </Button>
            </form>
          </div>
        </section>
    </div>
  );
}

function ChatHeader({
  conversation,
  isCustomer
}: {
  conversation: Conversation | ConversationSummary | null;
  isCustomer: boolean;
}) {
  const title =
    conversation && "customerName" in conversation
      ? conversation.customerName
      : isCustomer
        ? "Ev Bus Support"
        : "Select a conversation";

  return (
    <div className="flex items-center justify-between gap-3 border-b border-border bg-[#f7f3ed] px-3">
      <div className="flex min-w-0 items-center gap-3">
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
          {title.slice(0, 1).toUpperCase()}
        </div>
        <div className="min-w-0">
          <h2 className="truncate text-base font-semibold">{title}</h2>
          <p className="text-xs text-muted-foreground">
            {conversation?.status === "closed" ? "Closed conversation" : "Available support thread"}
          </p>
        </div>
      </div>
      <Button type="button" variant="ghost" size="icon" aria-label="Conversation menu">
        <MoreVertical className="h-4 w-4" />
      </Button>
    </div>
  );
}

function MessageBubble({ isOwn, item }: { isOwn: boolean; item: Message }) {
  return (
    <article
      className="grid w-[min(78%,620px)] gap-1 rounded-lg px-3 py-2 text-sm shadow-sm data-[own=false]:bg-white data-[own=true]:justify-self-end data-[own=true]:bg-[#d9fdd3]"
      data-own={isOwn}
    >
      <div className="flex min-w-0 items-center justify-between gap-3">
        <strong className="truncate text-[11px] text-muted-foreground">{item.senderName}</strong>
        <time className="shrink-0 text-[11px] text-muted-foreground" dateTime={item.createdAt}>
          {formatMessageTime(item.createdAt)}
        </time>
      </div>
      <p className="whitespace-pre-wrap leading-6 [overflow-wrap:anywhere]">{item.body}</p>
    </article>
  );
}

function formatMessageTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function StatusDot({ status }: { status: ConversationSummary["status"] }) {
  return (
    <span
      className="h-2.5 w-2.5 rounded-full data-[status=closed]:bg-amber-400 data-[status=open]:bg-emerald-500"
      data-status={status}
      aria-label={status}
    />
  );
}
