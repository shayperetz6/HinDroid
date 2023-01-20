import os, sys
import random
import time
from androguard.core.bytecodes import apk
from androguard.core.bytecodes.dvm import DalvikVMFormat, EncodedMethod, ClassDefItem
from androguard.core.analysis.analysis import ExternalMethod
import xml.etree.ElementTree as ET
import glob
import numpy as np

def get_apk_files(path: str):
    files = os.listdir(path)
    print(files)
    return [f for f in files if f.endswith(".apk")]

def rchop(s, sub):
    return s[:-len(sub)] if s.endswith(sub) else s

def lchop(s, sub):
    return s[len(sub):] if s.startswith(sub) else s

def inject_try_1(fn: str):
    # parse file name without apk
    fn_apk_les = rchop(fn, ".apk")
    # Decompile the APK to smali
    os.system(f"apktool d -f {fn_apk_les}.apk")
    
    # Make changes to the smali code.
    # For example, you can add a new line to call the API in the appropriate file.
    smali_file = glob.glob(f'{fn_apk_les}/smali/com/**/*.smali', recursive=True)[0]

    with open(smali_file, "a") as f:
        f.write("""# virtual methods
                    .method public mememe()V
                        .locals 4

                        .prologue
                        .line 294
                        sget-object v0, Lalpvir/orario/contatti;->mostCurrent:Lalpvir/orario/contatti;

                        if-eqz v0, :cond_0

                        sget-object v0, Lalpvir/orario/contatti;->mostCurrent:Lalpvir/orario/contatti;

                        iget-object v1, p0, Lalpvir/orario/contatti$ResumeMessage;->activity:Ljava/lang/ref/WeakReference;

                        invoke-virtual {v1}, Ljava/lang/ref/WeakReference;->get()Ljava/lang/Object;

                        move-result-object v1

                        if-eq v0, v1, :cond_1

                        .line 299
                        :cond_0
                        :goto_0
                        return-void

                        .line 296
                        :cond_1
                        sget-object v0, Lalpvir/orario/contatti;->processBA:Lanywheresoftware/b4a/BA;

                        const/4 v1, 0x0

                        invoke-virtual {v0, v1}, Lanywheresoftware/b4a/BA;->setActivityPaused(Z)V

                        .line 297
                        const-string v0, "** Activity (contatti) Resume **"

                        invoke-static {v0}, Lanywheresoftware/b4a/BA;->LogInfo(Ljava/lang/String;)V

                        .line 298
                        sget-object v1, Lalpvir/orario/contatti;->processBA:Lanywheresoftware/b4a/BA;

                        sget-object v0, Lalpvir/orario/contatti;->mostCurrent:Lalpvir/orario/contatti;

                        iget-object v2, v0, Lalpvir/orario/contatti;->_activity:Lanywheresoftware/b4a/objects/ActivityWrapper;

                        const-string v3, "activity_resume"

                        const/4 v0, 0x0

                        check-cast v0, [Ljava/lang/Object;

                        invoke-virtual {v1, v2, v3, v0}, Lanywheresoftware/b4a/BA;->raiseEvent(Ljava/lang/Object;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

                        goto :goto_0
                    .end method""")
                    

    # Recompile the APK
    os.system(f"apktool b {fn_apk_les}/")
    os.system(f"mv {fn_apk_les}/dist/{fn} ./mal-man")

def inject_from_list_apis(fn: str):
    # parse file name without apk
    fn_apk_les = rchop(fn, ".apk")
    # Decompile the APK to smali
    os.system(f"apktool d -f {fn_apk_les}.apk")
    
    methods = []
    with open('api.txt', 'r') as f:
        methods = f.readlines()
    methods = list(set(methods))
    methods = random.sample(methods, random.randint(7, 15))

    # Make changes to the smali code.
    # For example, you can add a new line to call the API in the appropriate file.
    smali_file = glob.glob(f'{fn_apk_les}/smali/com/**/*.smali', recursive=True)[0]
    
    methods = '\t'.join(methods)
    with open(smali_file, "a") as f:
        f.write(f"""# virtual methods
                    .method public mememe()V
                        .locals 4

                        .prologue
                        .line 294
                        
                        {methods}

                        goto :goto_0
                    .end method""")
                    

    # Recompile the APK
    os.system(f"apktool b {fn_apk_les}/")
    os.system(f"mv {fn_apk_les}/dist/{fn} ./mal-man")


from xml.dom.minidom import parseString
def get_main_page(app_dir: str):
    data = ''
    with open(f'{app_dir}/AndroidManifest.xml','r') as f:
        data = f.read()
    dom = parseString(data)
    activities = dom.getElementsByTagName('activity')
    perms = dom.getElementsByTagName('uses-permission')

    for activity in activities:
        m = str(activity.getAttribute('android:name'))
        if m.startswith("."):
            return m[1:]
    return ''

def main():
    choice = '1'
    apk_files = get_apk_files(".")
    if apk_files is not None and len(apk_files) > 0:
        print(rchop(file, ".apk"))
        # inject_try_1(file)
        # inject_try_2(file)
        for file in apk_files:
            try:
                if choice == '1':
                    inject_try_1(file)
                elif choice == '2':
                    inject_from_list_apis(file)
            except:
                pass



main()
