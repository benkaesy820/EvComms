import type { FormEvent } from "react";
import type { Conversation, ConversationSummary, Message, PublicUser } from "@evbus/shared";
import { MessageSquareText, RefreshCw, Send } from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
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
  const showInbox = user.role !== "customer";
  const canClose = user.role !== "customer" && selectedConversation?.status !== "closed";
  const canReassign = user.role === "super_admin" && Boolean(selectedConversation);
  const isClosed = selectedConversation?.status === "closed";

  return (
    <Card className="overflow-hidden">
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <MessageSquareText className="h-5 w-5 text-primary" />
              {user.role === "customer" ? "Support Thread" : "Conversation Workspace"}
            </CardTitle>
            <CardDescription>
              {user.role === "customer"
                ? "Your direct line to the Ev Bus team."
                : "WhatsApp-inspired inbox, customer thread, and operational controls."}
            </CardDescription>
          </div>
          {showInbox ? (
            <Button type="button" variant="outline" size="sm" onClick={onRefresh}>
              <RefreshCw className="h-4 w-4" />
              Refresh
            </Button>
          ) : null}
        </div>
      </CardHeader>

      <CardContent className="grid gap-0 p-0 xl:grid-cols-[300px_minmax(0,1fr)]">
        {showInbox ? (
          <aside className="border-b border-border bg-[#f0f4ef] xl:border-b-0 xl:border-r">
            <div className="flex items-center justify-between border-b border-border px-3 py-3">
              <span className="text-sm font-semibold">Inbox</span>
              <Badge variant="secondary">{conversations.length}</Badge>
            </div>
            <div className="grid max-h-[calc(100svh-210px)] min-h-[280px] gap-1 overflow-auto p-2">
              {conversations.length === 0 ? (
                <p className="rounded-md border border-dashed border-border bg-background p-3 text-sm text-muted-foreground">
                  {user.role === "agent" ? "No assigned conversations yet." : "No conversations yet."}
                </p>
              ) : (
                conversations.map((item) => (
                  <button
                    type="button"
                    className="grid gap-1 rounded-md px-3 py-2 text-left text-sm transition data-[active=true]:bg-white data-[active=true]:shadow-sm data-[active=false]:hover:bg-white/70"
                    data-active={item.id === selectedConversationId}
                    key={item.id}
                    onClick={() => onSelectConversation(item.id)}
                  >
                    <span className="flex items-center justify-between gap-2">
                      <strong className="truncate">{item.customerName}</strong>
                      <span className="text-[11px] text-muted-foreground">
                        {item.status === "closed" ? "Closed" : "Open"}
                      </span>
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

        <section className="grid min-w-0 grid-rows-[auto_minmax(360px,1fr)_auto] bg-[#efeae2]">
          <ChatHeader conversation={selectedConversation} isCustomer={user.role === "customer"} />

          <div className="grid content-start gap-3 overflow-auto p-3 md:p-4">
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

          <div className="border-t border-border bg-[#f7f3ed] p-3">
            {selectedConversation ? (
              <div className="mb-3 grid gap-2">
                {isClosed ? (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                    <span>This conversation is closed.</span>
                    <Button type="button" variant="outline" size="sm" onClick={onReopenConversation}>
                      Reopen
                    </Button>
                  </div>
                ) : null}

                {canReassign ? (
                  <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onReassign}>
                    <select
                      name="agentId"
                      className="h-10 rounded-md border border-input bg-background px-3 text-sm"
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
                    <Button type="submit" variant="outline">Reassign</Button>
                  </form>
                ) : null}

                {canClose ? (
                  <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onCloseConversation}>
                    <Input name="note" placeholder="Closing note" required maxLength={1000} />
                    <Button type="submit">Close</Button>
                  </form>
                ) : null}
              </div>
            ) : null}

            <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onSendMessage}>
              <Input
                name="body"
                placeholder={isClosed ? "Reopen this conversation before sending" : "Type a message"}
                required
                maxLength={5000}
                disabled={isClosed}
              />
              <Button type="submit" disabled={isClosed}>
                <Send className="h-4 w-4" />
                Send
              </Button>
            </form>
          </div>
        </section>
      </CardContent>
    </Card>
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
    <div className="flex items-center justify-between gap-3 border-b border-border bg-[#f7f3ed] px-4 py-3">
      <div className="min-w-0">
        <h2 className="truncate text-base font-semibold">{title}</h2>
        <p className="text-xs text-muted-foreground">
          {conversation?.status === "closed" ? "Closed conversation" : "Available support thread"}
        </p>
      </div>
      <Badge variant={conversation?.status === "closed" ? "warning" : "success"}>
        {conversation?.status ?? "open"}
      </Badge>
    </div>
  );
}

function MessageBubble({ isOwn, item }: { isOwn: boolean; item: Message }) {
  return (
    <article
      className="grid w-[min(86%,640px)] gap-1 rounded-md px-3 py-2 text-sm shadow-sm data-[own=false]:bg-white data-[own=true]:justify-self-end data-[own=true]:bg-[#d9fdd3]"
      data-own={isOwn}
    >
      <strong className="text-[11px] text-muted-foreground">{item.senderName}</strong>
      <p className="leading-6">{item.body}</p>
    </article>
  );
}
