1.ptrace方法第二个参数目标进程pid如果传入的是自己的会怎么样？
会出现operation not permitted，ptrace从原理上也是不能和finstrument结合使用的，__cyg_profile_func_enter是在应用进程内，在__cyg_profile_func_enter方法内就算获取到了寄存器rdi，rdi里存放的也是__cyg_profile_func_enter的第一个入参，不是追踪函数的入参。因为此时追踪函数的寄存器还没初始化正确，所以即使用汇编去获取也是没有意义。