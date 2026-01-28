// eslint-disable-next-line @typescript-eslint/naming-convention
import JAVA_VM_METHODS from "../data/java_vm.json";
import type { JNIMethod } from "./jni_method";

class JavaVM {
    private static instance: JavaVM | null;

    private readonly _methods: JNIMethod[];

    public constructor () {
        this._methods = JAVA_VM_METHODS;
    }

    public get methods (): JNIMethod[] {
        return this._methods;
    }

    public static getInstance (): JavaVM {
        return JavaVM.instance ??= new JavaVM();
    }
}

export { JavaVM };