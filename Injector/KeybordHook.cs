using PInvoke;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Hook
{
    /// <summary>
    /// 键盘钩子
    /// [以下代码来自某网友，并非本人原创]
    /// http://blog.csdn.net/u014434080/article/details/51513197
    /// </summary>
    public class KeyboardHook
    {
        public event KeyEventHandler KeyDownEvent;
        public event KeyPressEventHandler KeyPressEvent;
        public event KeyEventHandler KeyUpEvent;

        public delegate int HookProc(int nCode, Int32 wParam, IntPtr lParam);
        /// <summary>
        /// 注入成功的线程ID
        /// </summary>
        static int hKeyboardHook = 0; //声明键盘钩子处理的初始值
        //值在Microsoft SDK的Winuser.h里查询
        // http://www.bianceng.cn/Programming/csharp/201410/45484.htm
        public const int WH_KEYBOARD_LL = 13;   //线程键盘钩子监听鼠标消息设为2，全局键盘监听鼠标消息设为13
        HookProc KeyboardHookProcedure; //声明KeyboardHookProcedure作为HookProc类型
        //键盘结构
        [StructLayout(LayoutKind.Sequential)]
        public class KeyboardHookStruct
        {
            public int vkCode;  //定一个虚拟键码。该代码必须有一个价值的范围1至254
            public int scanCode; // 指定的硬件扫描码的关键
            public int flags;  // 键标志
            public int time; // 指定的时间戳记的这个讯息
            public int dwExtraInfo; // 指定额外信息相关的信息
        }
        //使用此功能，安装了一个钩子
        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hInstance, int threadId);


        //调用此函数卸载钩子
        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool UnhookWindowsHookEx(int idHook);


        //使用此功能，通过信息钩子继续下一个钩子
        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int CallNextHookEx(int idHook, int nCode, Int32 wParam, IntPtr lParam);

        // 取得当前线程编号（线程钩子需要用到）
        [DllImport("kernel32.dll")]
        static extern int GetCurrentThreadId();

        //使用WINDOWS API函数代替获取当前实例的函数,防止钩子失效
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string name);

        private int test(int c, IntPtr a, IntPtr b)
        {
            return User32.CallNextHookEx(new IntPtr(hKeyboardHook), c, a, b);
        }
        public void Start()
        {
            // 安装键盘钩子
            if (hKeyboardHook == 0)
            {
                KeyboardHookProcedure = new HookProc(KeyboardHookProc);
                hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProcedure, GetModuleHandle(Process.GetCurrentProcess().MainModule.ModuleName), 0);
                //hKeyboardHook = User32.SetWindowsHookEx(User32.WindowsHookType.WH_CALLWNDPROC,, Kernel32.GetModuleHandle(Process.GetCurrentProcess().MainModule.ModuleName).DangerousGetHandle(), 0).DangerousGetHandle().ToInt32();
                //hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProcedure, Marshal.GetHINSTANCE(Assembly.GetExecutingAssembly().GetModules()[0]), 0);
                /*
                 * 键盘线程钩子
                 * SetWindowsHookEx( 2,KeyboardHookProcedure, IntPtr.Zero, GetCurrentThreadId());//指定要监听的线程idGetCurrentThreadId(),
                 * 键盘全局钩子,需要引用空间(using System.Reflection;)
                 * SetWindowsHookEx( 13,MouseHookProcedure,Marshal.GetHINSTANCE(Assembly.GetExecutingAssembly().GetModules()[0]),0);
                 *
                 * 关于SetWindowsHookEx (int idHook, HookProc lpfn, IntPtr hInstance, int threadId)函数将钩子加入到钩子链表中，说明一下四个参数：
                 * idHook 钩子类型，即确定钩子监听何种消息，上面的代码中设为2，即监听键盘消息并且是线程钩子，如果是全局钩子监听键盘消息应设为13，
                 * 线程钩子监听鼠标消息设为7，全局钩子监听鼠标消息设为14。lpfn 钩子子程的地址指针。如果dwThreadId参数为0 或是一个由别的进程创建的
                 * 线程的标识，lpfn必须指向DLL中的钩子子程。 除此以外，lpfn可以指向当前进程的一段钩子子程代码。钩子函数的入口地址，当钩子钩到任何
                 * 消息后便调用这个函数。hInstance应用程序实例的句柄。标识包含lpfn所指的子程的DLL。如果threadId 标识当前进程创建的一个线程，而且子
                 * 程代码位于当前进程，hInstance必须为NULL。可以很简单的设定其为本应用程序的实例句柄。threaded 与安装的钩子子程相关联的线程的标识符
                 * 如果为0，钩子子程与所有的线程关联，即为全局钩子
                 *************************************
                 * 如果SetWindowsHookEx失败
                 */
                if (hKeyboardHook == 0)
                {
                    Stop();
                    throw new Exception("安装键盘钩子失败");
                }
            }
        }
        public void Stop()
        {
            bool retKeyboard = true;


            if (hKeyboardHook != 0)
            {
                retKeyboard = UnhookWindowsHookEx(hKeyboardHook);
                hKeyboardHook = 0;
            }

            if (!(retKeyboard)) throw new Exception("卸载钩子失败！");
        }
        //ToAscii职能的转换指定的虚拟键码和键盘状态的相应字符或字符
        [DllImport("user32")]
        public static extern int ToAscii(int uVirtKey, //[in] 指定虚拟关键代码进行翻译。
                                         int uScanCode, // [in] 指定的硬件扫描码的关键须翻译成英文。高阶位的这个值设定的关键，如果是（不压）
                                         byte[] lpbKeyState, // [in] 指针，以256字节数组，包含当前键盘的状态。每个元素（字节）的数组包含状态的一个关键。如果高阶位的字节是一套，关键是下跌（按下）。在低比特，如果设置表明，关键是对切换。在此功能，只有肘位的CAPS LOCK键是相关的。在切换状态的NUM个锁和滚动锁定键被忽略。
                                         byte[] lpwTransKey, // [out] 指针的缓冲区收到翻译字符或字符。
                                         int fuState); // [in] Specifies whether a menu is active. This parameter must be 1 if a menu is active, or 0 otherwise.

        //获取按键的状态
        [DllImport("user32")]
        public static extern int GetKeyboardState(byte[] pbKeyState);


        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern short GetKeyState(int vKey);

        private const int WM_KEYDOWN = 0x100;//KEYDOWN
        private const int WM_KEYUP = 0x101;//KEYUP
        private const int WM_SYSKEYDOWN = 0x104;//SYSKEYDOWN
        private const int WM_SYSKEYUP = 0x105;//SYSKEYUP

        private int KeyboardHookProc(int nCode, Int32 wParam, IntPtr lParam)
        {
            // 侦听键盘事件
            if ((nCode >= 0) && (KeyDownEvent != null || KeyUpEvent != null || KeyPressEvent != null))
            {
                KeyboardHookStruct MyKeyboardHookStruct = (KeyboardHookStruct)Marshal.PtrToStructure(lParam, typeof(KeyboardHookStruct));
                // raise KeyDown
                if (KeyDownEvent != null && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
                {
                    Keys keyData = (Keys)MyKeyboardHookStruct.vkCode;
                    KeyEventArgs e = new KeyEventArgs(keyData);
                    KeyDownEvent(this, e);
                }

                //键盘按下
                if (KeyPressEvent != null && wParam == WM_KEYDOWN)
                {
                    byte[] keyState = new byte[256];
                    GetKeyboardState(keyState);

                    byte[] inBuffer = new byte[2];

                    if (ToAscii(MyKeyboardHookStruct.vkCode, MyKeyboardHookStruct.scanCode, keyState, inBuffer, MyKeyboardHookStruct.flags) == 1)
                    {
                        KeyPressEventArgs e = new KeyPressEventArgs((char)inBuffer[0]);
                        KeyPressEvent(this, e);
                    }
                }

                // 键盘抬起
                if (KeyUpEvent != null && (wParam == WM_KEYUP || wParam == WM_SYSKEYUP))
                {
                    Keys keyData = (Keys)MyKeyboardHookStruct.vkCode;
                    KeyEventArgs e = new KeyEventArgs(keyData);
                    KeyUpEvent(this, e);
                }

            }
            //如果返回1，则结束消息，这个消息到此为止，不再传递。
            //如果返回0或调用CallNextHookEx函数则消息出了这个钩子继续往下传递，也就是传给消息真正的接受者
            return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
        }
        ~KeyboardHook()
        {
            Stop();
        }
    }

    /// <summary>
    /// 窗口消息钩子
    /// </summary>
    public class WindowHook
    {
        /// <summary>
        /// 注入成功后返回的线程ID
        /// </summary>
        int wHookId = 0;
        public EventHandler FormEvent;
        private delegate int HookProc(int nCode, IntPtr wParam, IntPtr lParam);
        //调用此函数卸载钩子
        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool UnhookWindowsHookEx(int idHook);
        private HookProc WindowsHookProceDure;

        /// <summary>
        /// 注册一个系统钩子
        /// </summary>
        /// <param name="idHook">注册的Hook类型</param>
        /// <param name="lnfp">回调过程</param>
        /// <param name="hMod">注入的模块指针</param>
        /// <param name="threadId">注入目标线程ID,为0时为全局钩子</param>
        /// <returns></returns>
        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern int SetWindowsHookEx(int idHook, HookProc lnfp, IntPtr hMod, int threadId);

        public void Start()
        {
            WindowsHookProceDure = new HookProc(WindowsHookProc);
            IntPtr lpfnHooker = Marshal.GetFunctionPointerForDelegate(WindowsHookProceDure);
            IntPtr hMod = Kernel32.GetModuleHandle(Process.GetCurrentProcess().MainModule.ModuleName).DangerousGetHandle();
            //最后一个参数为要注入的线程ID,为0时表示注册全局(系统)钩子
            User32.SafeHookHandle result = User32.SetWindowsHookEx(User32.WindowsHookType.WH_CBT, lpfnHooker, Kernel32.GetModuleHandle(new FileInfo("./Injector.dll").FullName).DangerousGetHandle(), 0);
            int error = Marshal.GetLastWin32Error();
            //wHookId = SetWindowsHookEx((int)User32.WindowsHookType.WH_CBT, WindowsHookProceDure, hMod, 0);
            if ((wHookId | result.DangerousGetHandle().ToInt32()) == 0)
            {
                throw new Exception("安装钩子失败");
            }
        }

        public void Stop()
        {
            if (!wHookId.Equals(0))
            {
                if (UnhookWindowsHookEx(wHookId))
                    wHookId = 0;
                else
                    throw new Exception("卸载钩子失败");
            }
        }

        #region 回调过程
        private int WindowsHookProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            //Something...
            return User32.CallNextHookEx(new IntPtr(wHookId), nCode, wParam, lParam);
        }
        #endregion
    }
}