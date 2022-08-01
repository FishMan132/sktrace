Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
    onEnter: function (args) {
        let arg0 = Memory.readCString(args[0])
        let arg1 = Memory.readCString(args[1])
        console.log('strncmp arg0: ', arg0);
        console.log('strncmp arg1: ', arg1);
        if (arg0.indexOf('17f104') != -1) {
            console.log('Context  : ' + JSON.stringify(this.context));
            // console.log('堆栈开始')
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
            // console.log('堆栈结束')
        }
    },
    onLeave: function (retval) {}
});