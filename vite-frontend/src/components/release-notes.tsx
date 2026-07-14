import ReactMarkdown from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import remarkGfm from "remark-gfm";

interface ReleaseNotesProps {
  body?: string | null;
}

export function ReleaseNotes({ body }: ReleaseNotesProps) {
  const content = body?.trim();

  return (
    <section className="rounded-2xl border border-white/60 bg-white/50 p-3 dark:border-white/10 dark:bg-white/10">
      <h3 className="mb-2 text-sm font-semibold">本次更新</h3>
      {content ? (
        <div className="max-h-64 overflow-y-auto break-words pr-1 text-xs leading-5 text-default-600 dark:text-default-300">
          <ReactMarkdown
            components={{
              h1: ({ children }) => (
                <h4 className="mb-2 text-sm font-bold text-foreground">
                  {children}
                </h4>
              ),
              h2: ({ children }) => (
                <h4 className="mb-1.5 mt-3 text-sm font-bold text-foreground first:mt-0">
                  {children}
                </h4>
              ),
              h3: ({ children }) => (
                <h5 className="mb-1 mt-2 font-semibold text-foreground">
                  {children}
                </h5>
              ),
              p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
              a: ({ children, href }) => (
                <a
                  className="text-primary underline underline-offset-2"
                  href={href}
                  rel="noopener noreferrer"
                  target="_blank"
                >
                  {children}
                </a>
              ),
              ul: ({ children }) => (
                <ul className="mb-2 list-disc space-y-1 pl-5 last:mb-0">
                  {children}
                </ul>
              ),
              ol: ({ children }) => (
                <ol className="mb-2 list-decimal space-y-1 pl-5 last:mb-0">
                  {children}
                </ol>
              ),
              code: ({ children }) => (
                <code className="rounded bg-default-100 px-1 py-0.5 font-mono text-[0.92em] dark:bg-white/10">
                  {children}
                </code>
              ),
              pre: ({ children }) => (
                <pre className="mb-2 overflow-x-auto rounded-lg bg-default-100 p-2.5 font-mono text-[11px] leading-5 dark:bg-black/25">
                  {children}
                </pre>
              ),
              blockquote: ({ children }) => (
                <blockquote className="mb-2 border-l-2 border-primary/50 pl-3 text-default-500">
                  {children}
                </blockquote>
              ),
            }}
            rehypePlugins={[rehypeSanitize]}
            remarkPlugins={[remarkGfm]}
          >
            {content}
          </ReactMarkdown>
        </div>
      ) : (
        <p className="text-xs text-default-500">此版本未提供更新说明。</p>
      )}
    </section>
  );
}
