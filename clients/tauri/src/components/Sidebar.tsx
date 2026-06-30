import { Shield } from "lucide-react";
import { NAV } from "../lib/nav";

export function Sidebar({ active, onSelect }: { active: string; onSelect: (id: string) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-logo"><Shield size={18} /></div>
        <div>
          <div className="brand-name">Nexus Defense IA</div>
          <div className="brand-sub">Command Center</div>
        </div>
      </div>
      <nav className="nav">
        {NAV.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`nav-item ${active === item.id ? "active" : ""}`}
              onClick={() => onSelect(item.id)}
            >
              <Icon className="nav-ico" />
              <span>{item.label}</span>
              {item.tag ? <span className="nav-tag">{item.tag}</span> : null}
            </button>
          );
        })}
      </nav>
      <div className="sidebar-foot">cliente Tauri · dados reais da API</div>
    </aside>
  );
}
