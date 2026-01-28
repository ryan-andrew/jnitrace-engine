class JNIThreadManager {
    private shadowJavaVM: NativePointer;

    private readonly threads: Map<number, NativePointer>;

    public constructor () {
        this.threads = new Map<number, NativePointer>();
        this.shadowJavaVM = NULL;
    }
    
    public getJavaVM (): NativePointer {
        return this.shadowJavaVM;
    }

    public hasJavaVM (): boolean {
        return !this.shadowJavaVM.isNull();
    }

    public setJavaVM (javaVM: NativePointer): void {
        this.shadowJavaVM = javaVM;
    }

    public getJNIEnv (threadId: number): NativePointer {
        const jniEnv = this.threads.get(threadId);
        if (jniEnv !== undefined) {
            return jniEnv;
        } else {
            return NULL;
        }
    }

    public hasJNIEnv (threadId: number): boolean {
        return !this.getJNIEnv(threadId).isNull();
    }

    public setJNIEnv (threadId: number, jniEnv: NativePointer): void {
        this.threads.set(threadId, jniEnv);
    }

    public needsJNIEnvUpdate (threadId: number, jniEnv: NativePointer): boolean {
        return this.threads.get(threadId)?.equals(jniEnv) !== true;
    }
}

export { JNIThreadManager };
