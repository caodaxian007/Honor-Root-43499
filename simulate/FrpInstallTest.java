import com.fne.universal.Frp;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

/** 纯 Java SE harness：实证 App 端 install() 的原子导入与失败保留语义。 */
public class FrpInstallTest {
    private static String md5(File f) throws Exception {
        if (!f.isFile()) return "MISSING";
        MessageDigest d = MessageDigest.getInstance("MD5");
        FileInputStream in = new FileInputStream(f);
        byte[] b = new byte[65536];
        int n;
        while ((n = in.read(b)) > 0) d.update(b, 0, n);
        in.close();
        StringBuilder s = new StringBuilder();
        for (byte x : d.digest()) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    private static void rmrf(File f) {
        if (!f.exists()) return;
        if (f.isDirectory()) {
            File[] cs = f.listFiles();
            if (cs != null) for (File c : cs) rmrf(c);
        }
        f.delete();
    }

    public static void main(String[] a) throws Exception {
        File dir = new File("/tmp/frp_install_test");
        rmrf(dir);
        dir.mkdirs();
        File good = new File(a[0]);   // 合法完整包
        File bad = new File(a[1]);    // 畸形包（校验必拒）
        File mf = new File(dir, "active_pkg/manifest.json");
        int fail = 0;

        Frp.Result r1 = Frp.install(good, dir);
        boolean c1 = r1.ok && mf.isFile();
        System.out.println((c1 ? "OK      " : "FAIL    ")
                + "首次导入成功，active_pkg 建立");
        if (!c1) fail++;

        String before = md5(mf);
        Frp.Result r2 = Frp.install(bad, dir);
        String after = md5(mf);
        boolean c2 = !r2.ok && before.equals(after) && !before.equals("MISSING");
        System.out.println((c2 ? "OK      " : "FAIL    ")
                + "畸形包被拒且原激活包逐字节未变（" + before.substring(0, 8) + "）");
        if (!c2) fail++;

        File payloadE = new File(dir, "active_pkg/payload/e");
        boolean c3 = payloadE.isFile() && payloadE.length() == 221104;
        System.out.println((c3 ? "OK      " : "FAIL    ")
                + "释放源 active_pkg/payload/e 完整（" + payloadE.length() + " B）");
        if (!c3) fail++;

        Frp.Result r3 = Frp.install(good, dir);
        boolean c4 = r3.ok && mf.isFile()
                && !new File(dir, "active_pkg.bak").exists()
                && !new File(dir, "active_pkg.tmp").exists()
                && !new File(dir, ".staging").exists();
        System.out.println((c4 ? "OK      " : "FAIL    ")
                + "重复导入正常替换，staging/tmp/bak 全部清理");
        if (!c4) fail++;

        System.out.println("fail=" + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
