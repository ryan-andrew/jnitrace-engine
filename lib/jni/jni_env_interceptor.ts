// eslint-disable-next-line @typescript-eslint/naming-convention
import JNI_ENV_METHODS from "../data/jni_env.json";

import type {JNIThreadManager} from "./jni_thread_manager";
import type {JavaVMInterceptor} from "./java_vm_interceptor";
import type {JNIMethod} from "./jni_method";

import type {ReferenceManager} from "../utils/reference_manager";
import {Types} from "../utils/types";
import {JavaMethod} from "../utils/java_method";
import {Config} from "../utils/config";

import type {JNIInvocationContext} from "../";
import type {JNICallbackManager} from "../internal/jni_callback_manager";

const TYPE_NAME_START = 0;
const TYPE_NAME_END = -1;
const COPY_ARRAY_INDEX = 0;
const JNI_ENV_INDEX = 0;

abstract class JNIEnvInterceptor {
    protected references: ReferenceManager;

    protected threads: JNIThreadManager;

    protected callbackManager: JNICallbackManager;

    protected javaVMInterceptor: JavaVMInterceptor | null;

    protected shadowJNIEnv: NativePointer;

    protected methods: Map<string, JavaMethod>;

    protected fastMethodLookup: Map<string, NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>>;

    protected vaArgsBacktraces: Map<number, NativePointer[]>;


    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        callbackManager: JNICallbackManager
    ) {
        this.references = references;
        this.threads = threads;
        this.callbackManager = callbackManager;

        this.javaVMInterceptor = null;

        this.shadowJNIEnv = NULL;
        this.methods = new Map<string, JavaMethod>();
        this.fastMethodLookup = new Map<string, NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>>();
        this.vaArgsBacktraces = new Map<number, NativePointer[]>();
    }

    public isInitialised (): boolean {
        return !this.shadowJNIEnv.equals(NULL);
    }

    public get (): NativePointer {
        return this.shadowJNIEnv;
    }

    public create (): NativePointer {
        const END_INDEX = 1;
        const threadId = Process.getCurrentThreadId();
        const jniEnv = this.threads.getJNIEnv(threadId);
        const jniEnvOffset = 4;
        const jniEnvLength = 232;

        const newJNIEnvStruct = Memory.alloc(Process.pointerSize * jniEnvLength);
        this.references.add(newJNIEnvStruct);

        const newJNIEnv = Memory.alloc(Process.pointerSize);
        newJNIEnv.writePointer(newJNIEnvStruct);
        this.references.add(newJNIEnv);

        for (let i = jniEnvOffset; i < jniEnvLength; i++) {
            const method = JNI_ENV_METHODS[i];
            const offset = i * Process.pointerSize;
            const jniEnvStruct = jniEnv.readPointer();
            const methodAddr = jniEnvStruct.add(offset).readPointer();

            if (method.args[method.args.length - END_INDEX] === "...") {
                const callback = this.createJNIVarArgIntercept(i, methodAddr);
                const trampoline = this.createStubFunction();
                this.references.add(trampoline);
                // ensure the CpuContext will be populated
                Interceptor.replace(trampoline, callback);
                newJNIEnvStruct.add(offset).writePointer(trampoline);
            } else {
                const callback = this.createJNIIntercept(i, methodAddr);
                const trampoline = this.createStubFunction();
                this.references.add(trampoline);
                // ensure the CpuContext will be populated
                Interceptor.replace(trampoline, callback);
                newJNIEnvStruct.add(offset).writePointer(trampoline);
            }
        }

        this.shadowJNIEnv = newJNIEnv;

        return newJNIEnv;
    }

    public setJavaVMInterceptor (javaVMInterceptor: JavaVMInterceptor): void {
        this.javaVMInterceptor = javaVMInterceptor;
    }

    // eslint-disable-next-line @typescript-eslint/class-methods-use-this
    public createStubFunction (): NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]> {
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        return new NativeCallback((): void => { }, "void", []);
    }

    protected createJNIVarArgIntercept (
        id: number,
        methodPtr: NativePointer
    ): NativePointer {
        const self = this;
        const method = JNI_ENV_METHODS[id];

        const text = Memory.alloc(Process.pageSize);
        const data = Memory.alloc(Process.pageSize);

        this.references.add(text);
        this.references.add(data);

        const vaArgsCallback = this.createJNIVarArgInitialCallback(
            method, methodPtr
        );

        this.references.add(vaArgsCallback);

        self.buildVaArgParserShellcode(text, data, vaArgsCallback);

        const config = Config.getInstance();

        Interceptor.attach(text, function (this: InvocationContext): void {
            let backtraceType = Backtracer.ACCURATE;
            if (config.backtrace === "fuzzy") {
                backtraceType = config.backtrace;
            }
            self.vaArgsBacktraces.set(
                this.threadId, Thread.backtrace(this.context, backtraceType)
            );
        });

        return text;
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-private-class-members
    private addJavaArgsForJNIIntercept (
        method: JNIMethod,
        args: NativeFunctionArgumentValue[]
    ): NativeFunctionArgumentValue[] {
        const LAST_INDEX = -1;
        const FIRST_INDEX = 0;
        const METHOD_ID_INDEX = 2;
        const NON_VIRTUAL_METHOD_ID_INDEX = 3;
        let methodIndex = METHOD_ID_INDEX;

        if (method.name.includes("Nonvirtual")) {
            methodIndex = NON_VIRTUAL_METHOD_ID_INDEX;
        }
        const lastParamType = method.args.slice(LAST_INDEX)[FIRST_INDEX];

        if (!["va_list", "jvalue*"].includes(lastParamType)) {
            return args.slice(COPY_ARRAY_INDEX);
        }

        const clonedArgs = args.slice(COPY_ARRAY_INDEX);
        const midPtr = Types.assertPtr(args[methodIndex], "midPtr");

        const javaMethod = this.methods.get(midPtr.toString());
        if (javaMethod == undefined) {
            send({
                type: "error",
                message: "Failed to find corresponding method ID " +
                    "for method \"" + method.name + "\" call."
            });
            return args.slice(COPY_ARRAY_INDEX);
        }

        const nativeJTypes = javaMethod.nativeParams;
        const readPtr = Types.assertPtr(args.slice(LAST_INDEX)[FIRST_INDEX], "readPtr");

        if (lastParamType === "va_list") {
            this.setUpVaListArgExtract(readPtr);
        }

        const UNION_SIZE = 8;
        for (let i = 0; i < nativeJTypes.length; i++) {
            const type = Types.convertNativeJTypeToFridaNativeFunctionArgumentType(nativeJTypes[i]);
            let val = undefined;
            if (lastParamType === "va_list") {
                const currentPtr = this.extractVaListArgValue(javaMethod, i);
                val = this.readValue(currentPtr, type, true);
            } else {
                val = this.readValue(readPtr.add(UNION_SIZE * i), type);
            }

            clonedArgs.push(val);
        }

        if (lastParamType === "va_list") {
            this.resetVaListArgExtract();
        }

        return clonedArgs;
    }

    private handleGetMethodResult (
        args: NativeFunctionArgumentValue[],
        ret: NativeFunctionReturnValue
    ): void {
        const SIG_INDEX = 3;
        const signature = Types.assertPtr(args[SIG_INDEX], "sigPtr").readCString();

        if (signature !== null) {
            const methodSig = new JavaMethod(signature);
            this.methods.set(Types.assertPtr(ret, "ret").toString(), methodSig);
        }
    }

    private handleGetJavaVM (
        args: NativeFunctionArgumentValue[],
        ret: NativeFunctionReturnValue
    ): void {
        if (this.javaVMInterceptor !== null) {
            const JNI_OK = 0;
            const JAVA_VM_INDEX = 1;

            if (ret === JNI_OK) {
                const javaVMPtr = Types.assertPtr(args[JAVA_VM_INDEX], "javaVMPtr");
                this.threads.setJavaVM(javaVMPtr.readPointer());

                let javaVM = undefined;
                if (!this.javaVMInterceptor.isInitialised()) {
                    javaVM = this.javaVMInterceptor.create();
                } else {
                    javaVM = this.javaVMInterceptor.get();
                }

                javaVMPtr.writePointer(javaVM);
            }
        }
    }

    private handleRegisterNatives (args: NativeFunctionArgumentValue[]): void {
        const METHOD_INDEX = 2;
        const SIZE_INDEX = 3;
        const JNI_METHOD_SIZE = 3;

        const self = this;

        const methods = Types.assertPtr(args[METHOD_INDEX], "methods");
        const size = Types.assertNum(args[SIZE_INDEX], "size");
        for (let i = 0; i < size * JNI_METHOD_SIZE; i += JNI_METHOD_SIZE) {
            const methodsPtr = methods;

            const namePtr = methodsPtr
                .add(i * Process.pointerSize)
                .readPointer();
            const name = namePtr.readCString();

            const sigOffset = 1;
            const sigPtr = methodsPtr
                .add((i + sigOffset) * Process.pointerSize)
                .readPointer();
            const sig = sigPtr.readCString();

            const addrOffset = 2;
            const addr = methodsPtr
                .add((i + addrOffset) * Process.pointerSize)
                .readPointer();

            if (name === null || sig === null) {
                continue;
            }

            Interceptor.attach(addr, {
                onEnter (iArgs: InvocationArguments): void {
                    const check = name + sig;
                    const config = Config.getInstance();
                    const EMPTY_ARRAY_LEN = 0;

                    if (config.includeExport.length > EMPTY_ARRAY_LEN) {
                        const included = config.includeExport.filter(
                            (j: string): boolean => check.includes(j)
                        );
                        if (included.length === EMPTY_ARRAY_LEN) {
                            return;
                        }
                    }
                    if (config.excludeExport.length > EMPTY_ARRAY_LEN) {
                        const excluded = config.excludeExport.filter(
                            (e: string): boolean => check.includes(e)
                        );
                        if (excluded.length > EMPTY_ARRAY_LEN) {
                            return;
                        }
                    }

                    if (!self.threads.hasJNIEnv(this.threadId)) {
                        self.threads.setJNIEnv(
                            this.threadId, iArgs[JNI_ENV_INDEX]
                        );
                    }
                    iArgs[JNI_ENV_INDEX] = self.shadowJNIEnv;
                }
            });
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-private-class-members
    private handleJNIInterceptResult (
        method: JNIMethod,
        args: NativeFunctionArgumentValue[],
        ret: NativeFunctionReturnValue
    ): void {
        const {name} = method;

        if (["GetMethodID", "GetStaticMethodID"].includes(name)) {
            this.handleGetMethodResult(args, ret);
        } else if (method.name === "GetJavaVM") {
            this.handleGetJavaVM(args, ret);
        } else if (method.name === "RegisterNatives") {
            this.handleRegisterNatives(args);
        }
    }

    private createJNIIntercept (
        id: number,
        methodPtr: NativePointer
    ): NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]> {
        const self = this;
        const METHOD_ID_INDEX = 2;
        const method = JNI_ENV_METHODS[id];
        const config = Config.getInstance();

        const paramTypes = method.args.map(
            (t: string): NativeFunctionArgumentType => Types.convertNativeJTypeToFridaNativeFunctionArgumentType(t)
        );
        const retType = Types.convertNativeJTypeToFridaNativeFunctionReturnType(method.ret);

        const nativeFunction = new NativeFunction(
            methodPtr,
            retType,
            paramTypes
        ) as NativeFunction<
            NativeFunctionReturnValue,
            NativeFunctionArgumentValue[]
        >;
        const callbackArgs = Types.assertHasNoVariadicTypes(paramTypes, "paramTypes")
        const nativeCallback = new NativeCallback(function (
            this: InvocationContext | CallbackContext,
            ...args: NativeCallbackArgumentValue[]
        ): NativeCallbackReturnValue {
            if (!Types.isInvocationContext(this)) {
                throw new Error("This is not an invocation context somehow")
            }
            const jniEnv = self.threads.getJNIEnv(this.threadId);
            const mutableArgs = Array.from(args);

            mutableArgs[JNI_ENV_INDEX] = jniEnv;

            const clonedArgs = self.addJavaArgsForJNIIntercept(method, mutableArgs);

            const ctx: JNIInvocationContext = {
                jniAddress: methodPtr,
                threadId: this.threadId,
                methodDef: method,
            };

            if (config.backtrace === "accurate") {
                ctx.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
            } else if (config.backtrace === "fuzzy") {
                ctx.backtrace = Thread.backtrace(this.context, Backtracer.FUZZY);
            }

            if (mutableArgs.length !== clonedArgs.length) {
                // eslint-disable-next-line @typescript-eslint/no-base-to-string
                const key = mutableArgs[METHOD_ID_INDEX]?.toString();
                if (key == undefined) {
                    throw new Error("Method ID somehow not found")
                }
                ctx.javaMethod = self.methods.get(key);
            }

            self.callbackManager.doBeforeCallback(method.name, ctx, clonedArgs);

            // eslint-disable-next-line prefer-spread
            let ret = nativeFunction.apply(null, mutableArgs);

            ret = self.callbackManager.doAfterCallback(method.name, ctx, ret);

            self.handleJNIInterceptResult(method, mutableArgs, ret);

            return ret;
        }, retType, callbackArgs);

        this.references.add(nativeCallback);

        return nativeCallback;
    }

    // eslint-disable-next-line @typescript-eslint/max-params,@typescript-eslint/no-unused-private-class-members
    private createJNIVarArgMainCallback (
        method: JNIMethod,
        methodPtr: NativePointer,
        initialparamTypes: NativeFunctionArgumentType[],
        mainParamTypes: NativeCallbackArgumentType[],
        retType: NativeFunctionReturnType
    ): NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]> {
        const self = this;

        return new NativeCallback(function (
            this: InvocationContext | CallbackContext,
            ...args: NativeCallbackArgumentValue[]
        ): NativeCallbackReturnValue {
            const METHOD_ID_INDEX = 2;
            if (!Types.isInvocationContext(this)) {
                throw new Error("This is not an invocation context somehow")
            }
            const mutableArgs = Array.from(args);
            const jniEnv = self.threads.getJNIEnv(this.threadId);
            // eslint-disable-next-line @typescript-eslint/no-base-to-string
            const key = mutableArgs[METHOD_ID_INDEX]?.toString();
            if (key == undefined) {
                throw new Error("Method ID somehow not found")
            }
            const jmethod = self.methods.get(key);

            mutableArgs[JNI_ENV_INDEX] = jniEnv;

            const ctx: JNIInvocationContext = {
                backtrace: self.vaArgsBacktraces.get(this.threadId),
                jniAddress: methodPtr,
                threadId: this.threadId,
                methodDef: method,
                javaMethod: jmethod
            };

            self.callbackManager.doBeforeCallback(method.name, ctx, mutableArgs);

            const nativeFunction = new NativeFunction(
                methodPtr,
                retType,
                initialparamTypes
            ) as NativeFunction<NativeFunctionReturnValue, NativeFunctionArgumentValue[]>;
            // eslint-disable-next-line prefer-spread
            let ret = nativeFunction.apply(null, mutableArgs);

            ret = self.callbackManager.doAfterCallback(method.name, ctx, ret);

            self.vaArgsBacktraces.delete(this.threadId);

            return ret;
        }, retType, mainParamTypes);
    }

    private createJNIVarArgInitialCallback (
        method: JNIMethod,
        methodPtr: NativePointer
    ): NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]> {
        const self = this;

        return new NativeCallback(function (
            this: InvocationContext | CallbackContext,
            ...args: NativeCallbackArgumentValue[]
        ): NativePointerValue {
            const METHOD_ID_INDEX = 2;
            // eslint-disable-next-line @typescript-eslint/no-base-to-string
            const methodId = args[METHOD_ID_INDEX]?.toString();
            if (methodId == undefined) {
                throw new Error("methodId was somehow undefined")
            }
            const javaMethod = self.methods.get(methodId);
            if (javaMethod == undefined) {
                throw new Error("Method ID not found in cache")
            }

            const fastMethod = self.fastMethodLookup.get(methodId);
            if (fastMethod !== undefined) {
                return fastMethod;
            }

            const originalParams = method.args
                .slice(TYPE_NAME_START, TYPE_NAME_END)
                .map((t) => Types.convertNativeJTypeToFridaNativeFunctionArgumentType(t));

            const callbackParams = Types.assertHasNoVariadicTypes(originalParams.slice(COPY_ARRAY_INDEX), "");

            originalParams.push("...");

            javaMethod.fridaParams.forEach((p: NativeFunctionArgumentType): void => {
                const param = p === "float" ? "double" : p;
                callbackParams.push(Types.assertIsNotVariadicType(param, "param"));
                originalParams.push(param as NativeFunctionArgumentType);
            });

            const retType = Types.convertNativeJTypeToFridaNativeFunctionReturnType(method.ret);

            const mainCallback = self.createJNIVarArgMainCallback(
                method, methodPtr, originalParams, callbackParams, retType
            );
            self.references.add(mainCallback);

            self.fastMethodLookup.set(methodId, mainCallback);

            return mainCallback;
        }, "pointer", ["pointer", "pointer", "pointer"]);
    }

    // eslint-disable-next-line @typescript-eslint/class-methods-use-this
    private readValue (
        currentPtr: NativePointer,
        type: NativeFunctionArgumentType,
        extend?: boolean
    ): NativeFunctionArgumentValue {
        let val: NativeFunctionArgumentValue = NULL;

        if (type === "char") {
            val = currentPtr.readS8();
        } else if (type === "int16") {
            val = currentPtr.readS16();
        } else if (type === "uint16") {
            val = currentPtr.readU16();
        } else if (type === "int") {
            val = currentPtr.readS32();
        } else if (type === "int64") {
            val = currentPtr.readS64();
        } else if (type === "float") {
            if (extend === true) {
                val = currentPtr.readDouble();
            } else {
                val = currentPtr.readFloat();
            }
        } else if (type === "double") {
            val = currentPtr.readDouble();
        } else if (type === "pointer") {
            val = currentPtr.readPointer();
        }

        return val;
    }

    protected abstract buildVaArgParserShellcode(
        text: NativePointer,
        data: NativePointer,
        parser: NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>
    ): void;

    protected abstract setUpVaListArgExtract(vaList: NativePointer): void;

    protected abstract extractVaListArgValue(
        method: JavaMethod,
        index: number
    ): NativePointer;

    protected abstract resetVaListArgExtract(): void;
}

export { JNIEnvInterceptor };
