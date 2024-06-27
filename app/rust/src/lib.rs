use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;

use memfd_exec::{MemFdExecutable, Stdio};
use qemu::QEMU_RISCV64_LINUX_USER;

use std::env::args;
use std::fs::read;
//use std::io::Read;

#[macro_use] extern crate log;
extern crate android_log;

#[no_mangle]
pub extern "system" fn Java_xyz_proofcast_tee_1vm_MainActivity_runVM<'local>(
    mut env: JNIEnv<'local>,
    class: JClass<'local>,
    input: JString<'local>)
    -> jstring {

    android_log::init("tee-vm").unwrap();

    //let input: String =
    //    env.get_string(&input).expect("Couldn't get java string!").into();

    //let output = env.new_string(format!("Hello, {}!", input))
    //    .expect("Couldn't create java string!");

    //output.into_raw()
    info!("test info ciao!");
    let ls_contents = read("/bin/ls").expect("Could not read /bin/ls");

    let input: String = env.get_string(&input).expect("Couldn't get java string!").into();
    let output = env.new_string(format!("Hello, {}!", input))
               .expect("Couldn't create java string!");
    let qemu = QEMU_RISCV64_LINUX_USER;
    let mut args: Vec<String> = args().collect();
    args.push(input);

    let _ls = MemFdExecutable::new("ls", &ls_contents)
        .arg(".")
        .spawn()
        .expect("Failed to run ls");
    //let mut qemu = MemFdExecutable::new("qemu-riscv64", qemu)
        //.args(args);
        // .stdin(Stdio::null())
        //.stdout(Stdio::piped())
        // .stderr(Stdio::piped())
        //.spawn();
        //.unwrap();

    //let vm_output = qemu.wait_with_output().unwrap();

    //let output = env.new_string(String::from_utf8_lossy(&vm_output.stdout))
    //    .expect("Couldn't create java string!");



    output.into_raw()
}