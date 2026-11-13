import com.fne.universal.Frp;

import java.io.File;

/**
 * 纯 Java SE harness —— Frp.verify() 只依赖 java.io / java.util / java.util.zip /
 * java.security / org.json，不 import 任何 android.* 类，因此能在云电脑里直接跑，
 * 真实执行 App 端那份校验器（不是静态看代码、也不是用 Python 规则代替）。
 *
 * 用法：java FrpVerifyTest "<包路径>:<期望1=接受/0=拒绝>" ...
 * 返回码 0 表示所有用例结论与期望一致。
 */
public class FrpVerifyTest {
    public static void main(String[] args) {
        int mismatch = 0;
        for (String a : args) {
            int c = a.lastIndexOf(':');
            if (c < 1) { System.out.println("BADARG " + a); mismatch++; continue; }
            String path = a.substring(0, c);
            boolean expect = a.substring(c + 1).equals("1");
            Frp.Result r;
            try {
                r = Frp.verify(new File(path));
            } catch (Throwable t) {
                System.out.println("CRASH   " + new File(path).getName()
                        + " :: " + t.getClass().getName() + " " + t.getMessage());
                mismatch++;
                continue;
            }
            boolean ok = r.ok;
            boolean good = (ok == expect);
            if (!good) mismatch++;
            System.out.println((good ? "OK      " : "MISMATCH")
                    + (ok ? "ACCEPT" : "REJECT") + "  "
                    + new File(path).getName());
        }
        System.out.println("mismatch=" + mismatch);
        System.exit(mismatch == 0 ? 0 : 1);
    }
}
