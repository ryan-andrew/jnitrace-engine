// eslint-disable-next-line @typescript-eslint/naming-convention
import JNI_ENV_METHODS from "../data/jni_env.json";
import type { JNIMethod } from "./jni_method";

class JNIEnv {
    private static instance: JNIEnv | null;

    private readonly _methods: JNIMethod[];

    public constructor () {
        this._methods = JNI_ENV_METHODS;
    }

    public get methods (): JNIMethod[] {
        return this._methods;
    }

    public static getInstance (): JNIEnv {
        return JNIEnv.instance ??= new JNIEnv();
    }
}

export { JNIEnv };