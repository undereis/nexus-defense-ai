import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

export function DataPanel({
  title, icon: Icon, actions, tight, children,
}: {
  title: string;
  icon?: LucideIcon;
  actions?: ReactNode;
  tight?: boolean;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        {Icon ? <Icon className="head-ico" /> : null}
        <h3>{title}</h3>
        <span className="spacer" />
        {actions}
      </div>
      <div className={`panel-body${tight ? " tight" : ""}`}>{children}</div>
    </section>
  );
}
