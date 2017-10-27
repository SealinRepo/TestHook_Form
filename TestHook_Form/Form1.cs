using System;
using System.Windows.Forms;

namespace Hook
{
    public partial class Form1 : Form
    {
        KeyboardHook kHook = new KeyboardHook();
        WindowHook wHook = new WindowHook();
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.FormClosing += new FormClosingEventHandler(Form_Unload);
            wHook.FormEvent += new EventHandler(Window_Event);
            //kHook.KeyPressEvent += new KeyPressEventHandler(Keypress_Event);
            //kHook.Start();
            try
            {
                wHook.Start();
            }
            catch (Exception exception)
            {
                label1.Text = exception.Message;
            }
        }

        private void Keypress_Event(object o, KeyPressEventArgs e)
        {
            label1.Text = e.KeyChar.ToString();
        }

        private void Window_Event(object o, EventArgs e)
        {
            label1.Text += e.ToString();
        }

        /// <summary>
        /// 窗口关闭
        /// </summary>
        private void Form_Unload(object o, FormClosingEventArgs e)
        {
            //hook.Stop();
            wHook.Stop();
        }


    }
}
