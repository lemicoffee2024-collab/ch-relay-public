import { useState } from "react";
import { api, errMsg, type LicenseRow } from "../lib/api.ts";
import { usePoll } from "../lib/hooks.ts";
import { Button, Card, PageHeader, Skeleton, useToast } from "../components/ui.tsx";
import { num } from "../lib/format.ts";

const fmtDay = (t: number | null) => (t ? new Date(t).toLocaleString("vi-VN", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "—");

export function LicensesPage() {
  const toast = useToast();
  const lic = usePoll(() => api.licenseList(), 15_000, "licenses");
  const [adminKey, setAdminKey] = useState("");
  const [label, setLabel] = useState("");
  const [days, setDays] = useState("30");
  const [busy, setBusy] = useState(false);
  const [extDays, setExtDays] = useState<Record<string, string>>({});

  const saveAdminKey = async () => {
    setBusy(true);
    try {
      await api.saveLicenseAdminKey(adminKey.trim());
      setAdminKey("");
      toast("success", "Đã lưu admin key");
      await lic.reload();
    } catch (e) {
      toast("error", "Lưu thất bại", errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const mint = async () => {
    setBusy(true);
    try {
      const d = Number(days);
      const expiresAt = d > 0 ? Date.now() + d * 86400_000 : null;
      const r = await api.mintLicense({ label: label.trim() || undefined, expiresAt });
      toast("success", `Đã cấp key ${r.key.slice(0, 12)}…`, "Copy gửi cho khách — key chỉ hiện ở đây.");
      setLabel("");
      await lic.reload();
    } catch (e) {
      toast("error", "Cấp key thất bại", errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try {
      await fn();
      toast("success", ok);
      await lic.reload();
    } catch (e) {
      toast("error", "Thao tác thất bại", errMsg(e));
    }
  };

  const d = lic.data;
  if (d && "configured" in d && !d.configured) {
    return (
      <div className="page">
        <PageHeader title="Licenses" subtitle="Cấp / thu hồi / gia hạn key cho khách." />
        <Card>
          <p className="dim">Chưa có admin key — dán <code>CH_POLICY_ADMIN_KEY</code> của policy-server vào đây (lưu 1 lần):</p>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <input className="inline-input" style={{ flex: 1 }} placeholder="admin key" value={adminKey} onChange={(e) => setAdminKey(e.target.value)} spellCheck={false} />
            <Button size="sm" busy={busy} disabled={!adminKey.trim()} onClick={() => void saveAdminKey()}>Lưu</Button>
          </div>
        </Card>
      </div>
    );
  }

  const rows = d?.licenses ?? [];
  return (
    <div className="page wide">
      <PageHeader title="Licenses" subtitle="Cấp / thu hồi / gia hạn key cho khách." />

      <Card>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input className="inline-input" style={{ flex: 2, minWidth: 180 }} placeholder="Label (tên khách)" value={label} onChange={(e) => setLabel(e.target.value)} />
          <input className="inline-input" style={{ width: 110 }} type="number" min={0} placeholder="Số ngày" value={days} onChange={(e) => setDays(e.target.value)} title="0 = vĩnh viễn" />
          <Button size="sm" busy={busy} onClick={() => void mint()}>Cấp key mới</Button>
        </div>
      </Card>

      <Card style={{ marginTop: 16 }}>
        {lic.loading && !d ? (
          <Skeleton h={120} />
        ) : rows.length === 0 ? (
          <div className="dim">Chưa có key nào.</div>
        ) : (
          <table className="tbl">
            <thead>
              <tr><th>Key</th><th>Khách</th><th>Máy</th><th>Lượt xài</th><th>Hoạt động cuối</th><th>Hết hạn</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const dead = !!r.revoked || (r.expires_at !== null && r.expires_at <= Date.now());
                return (
                  <tr key={r.key} className={dead ? "dim" : ""}>
                    <td className="mono">
                      {r.key.slice(0, 14)}…
                      <button className="icon-btn subtle" title="Sao chép" onClick={() => void navigator.clipboard.writeText(r.key).then(() => toast("success", "Đã sao chép"), () => {})}>⧉</button>
                    </td>
                    <td>
                      {r.label ?? "—"}
                      {r.flags > 0 && <span title={`${r.flags} lần mò secret — khách đã moi được một phần recipe`} style={{ marginLeft: 6, color: "#e5484d" }}>⚑{r.flags}</span>}
                    </td>
                    <td title="Số máy đã kích hoạt / giới hạn">{r.devices}/{r.max_devices ?? 3}</td>
                    <td>{num(r.uses)}</td>
                    <td>{fmtDay(r.last_seen_at)}</td>
                    <td>
                      {r.revoked ? "đã thu hồi" : r.expires_at === null ? "vĩnh viễn" : fmtDay(r.expires_at)}
                    </td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {!r.revoked && (
                        <>
                          <input
                            className="inline-input"
                            style={{ width: 70 }}
                            type="number" min={1}
                            placeholder="+ngày"
                            value={extDays[r.key] ?? ""}
                            onChange={(e) => setExtDays({ ...extDays, [r.key]: e.target.value })}
                          />
                          <Button size="sm" variant="plain" disabled={!Number(extDays[r.key] ?? 0)} onClick={() => void act(() => api.extendLicense(r.key, { expiresAt: Date.now() + Number(extDays[r.key]) * 86400_000 }), "Đã gia hạn")}>
                            Gia hạn
                          </Button>
                          <Button size="sm" variant="plain" disabled={!r.devices} title="Xoá danh sách máy đã gắn — dùng khi khách đổi máy/cài lại" onClick={() => void act(() => api.resetLicenseDevices(r.key), "Đã reset máy")}>
                            Reset máy
                          </Button>
                          <Button size="sm" variant="plain" onClick={() => void act(() => api.revokeLicense(r.key), "Đã thu hồi")}>
                            Thu hồi
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
