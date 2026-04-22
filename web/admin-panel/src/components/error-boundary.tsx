import { Component, type ReactNode, type ErrorInfo } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  info: ErrorInfo | null;
}

// Catches render errors anywhere under it and renders the raw error + stack
// trace in-page. Purely a diagnostic tool: without it, a React render error
// produces a blank screen with only a minified bundle location in the console.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: null };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    this.setState({ error, info });
    console.error("[ErrorBoundary]", error, info);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div
          style={{
            padding: 24,
            fontFamily: "ui-monospace, monospace",
            fontSize: 12,
            background: "#fff1f0",
            color: "#a8071a",
            minHeight: "100vh",
            overflow: "auto",
          }}
        >
          <h1 style={{ fontFamily: "system-ui" }}>Render error</h1>
          <p>
            <strong>{this.state.error.name}:</strong> {this.state.error.message}
          </p>
          <h3 style={{ fontFamily: "system-ui" }}>Error stack</h3>
          <pre style={{ whiteSpace: "pre-wrap" }}>{this.state.error.stack}</pre>
          {this.state.info && (
            <>
              <h3 style={{ fontFamily: "system-ui" }}>Component stack</h3>
              <pre style={{ whiteSpace: "pre-wrap" }}>{this.state.info.componentStack}</pre>
            </>
          )}
        </div>
      );
    }
    return this.props.children;
  }
}
