from tkinter import *
import sqlite3

def Train():
    """GUI"""
    import tkinter as tk
    import numpy as np
    import pandas as pd

    from sklearn.decomposition import PCA
    from sklearn.preprocessing import LabelEncoder

    root = tk.Tk()

    w, h = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry("%dx%d+0+0" % (w, h))
    root.title("Malicious Application Prediction")
    root.configure(background="white")
    lbl = tk.Label(root, text="Malicious Application Detection", font=('times', 30,' bold italic '), height=1, width=60,bg="white",fg="black")
    lbl.place(x=0, y=0)   
    
    index_var = tk.IntVar()
    
    tele_device = tk.IntVar()
    tele_subscriber = tk.IntVar()
    abort = tk.IntVar()
    sendsms = tk.IntVar()
    delete_pack = tk.IntVar()
    sms_received = tk.IntVar()
    ljava = tk.IntVar()
    phone_s= tk.IntVar()
    readsms = tk.IntVar()
    boot_comp = tk.IntVar()
    io_delete = tk.IntVar()
    chown = tk.IntVar()
    chmod = tk.IntVar()
    mount = tk.IntVar()
    apk = tk.IntVar()
    zip_file = tk.IntVar()
    dex_file= tk.IntVar()
    camera = tk.IntVar()
    access = tk.IntVar()
    package = tk.IntVar()
    battery_low = tk.IntVar()
    so_file = tk.IntVar()
    power_connec = tk.IntVar()
    load_lib = tk.IntVar()
    exe_file = tk.IntVar()
    




    #===================================================================================================================
    def fetchData():
        db = sqlite3.connect('fetch_db.db')
        cursor = db.cursor()
        
        cursor.execute("select * from fetch_data WHERE id = ?",[(index_var.get())])
        db.commit()

        fetchData = cursor.fetchall()

        if not fetchData:
            print("not present")
        else:
            print("fetch data =",fetchData)
            print("input =",index_var.get())


            tele_device.delete(0,tk.END)
            tele_subscriber.delete(0,tk.END)
            abort.delete(0,tk.END)
            sendsms.delete(0,tk.END)
            delete_pack.delete(0,tk.END)
            sms_received.delete(0,tk.END)
            ljava.delete(0,tk.END)
            phone_s.delete(0,tk.END)
            readsms.delete(0,tk.END)
            boot_comp.delete(0,tk.END)
            io_delete.delete(0,tk.END)
            chown.delete(0,tk.END)
            chmod.delete(0,tk.END)
            mount.delete(0,tk.END)
            apk.delete(0,tk.END)
            zip_file.delete(0,tk.END)
            dex_file.delete(0,tk.END)
            camera.delete(0,tk.END)
            access.delete(0,tk.END)
            package.delete(0,tk.END)
            battery_low.delete(0,tk.END)
            so_file.delete(0,tk.END)
            power_connec.delete(0,tk.END)
            load_lib.delete(0,tk.END)
            exe_file.delete(0,tk.END)






            
            inputData = fetchData[0]
            tele_device.insert(tk.END,inputData[1])
            tele_subscriber.insert(tk.END,inputData[2])
            abort.insert(tk.END,inputData[3])
            sendsms.insert(tk.END,inputData[4])
            delete_pack.insert(tk.END,inputData[5])
            sms_received.insert(tk.END,inputData[6])
            ljava.insert(tk.END,inputData[7])
            phone_s.insert(tk.END,inputData[8])
            readsms.insert(tk.END,inputData[9])
            boot_comp.insert(tk.END,inputData[10])
            io_delete.insert(tk.END,inputData[11])
            chown.insert(tk.END,inputData[12])
            chmod.insert(tk.END,inputData[13])
            mount.insert(tk.END,inputData[14])
            apk.insert(tk.END,inputData[15])
            zip_file.insert(tk.END,inputData[16])
            dex_file.insert(tk.END,inputData[17])
            camera.insert(tk.END,inputData[18])
            access.insert(tk.END,inputData[19])
            package.insert(tk.END,inputData[20])
            battery_low.insert(tk.END,inputData[21])
            so_file.insert(tk.END,inputData[22])
            power_connec.insert(tk.END,inputData[23])
            load_lib.insert(tk.END,inputData[24])
            exe_file.insert(tk.END,inputData[25])





    #===================================================================================================================
    def Detect():
        e1=tele_device.get()
        print(e1)
        e2=tele_subscriber.get()
        print(e2)
        e3=abort.get()
        print(e3)
        #print(type(e3))
        e4=sendsms.get()
        print(e4)
        e5=delete_pack.get()
        print(e5)
        e25=phone_s.get()
        print(e5)
        e6=sms_received.get()
        print(e6)
        e7=ljava.get()
        print(e7)
        e8=readsms.get()
        print(e8)
        e9=boot_comp.get()
        print(e9)
        e10=io_delete.get()
        print(e10)
        e11=chown.get() 
        print(e11)
        e12=chmod.get()
        print(e12)
        e13=mount.get()
        print(e13)
    
        e14=apk.get()
        print(e14)
        e15=zip_file.get()
        print(e15)
        e16=dex_file.get()
        print(e16)    
        e17=camera.get()
        print(e17)
        e18=access.get()
        print(e18)
        e19=package.get()
        print(e19)
        e20=battery_low.get()
        print(e20)
        
        e21=so_file.get()
        print(e21)
        e22=power_connec.get()
        print(e22)
        e23=load_lib.get()
        print(e23)
        e24=exe_file.get()
        print(e24)

        
        
        
        #########################################################################################
        
        from joblib import dump , load
        a1=load('botnet_MODEL.joblib')
        v= a1.predict([[e1, e2, e3, e4, e5,e25, e6, e7, e8, e9,e10, e11, e12, e13,e14, e15, e16, e17, e18, e19, e20, e21, e22,e23, e24]])
        print(v)
        if v[0]==1:
            print("Yes")
            yes = tk.Label(root,text="Malicious Application Predicted",background="white",foreground="red",font=('times', 18, ' bold underline '),width=35)
            yes.place(x=500,y=630)
                     
        else:
            print("No")
            no = tk.Label(root, text="No Malicious Application Predicted", background="white", foreground="green",font=('times', 18, 'bold underline '),width=35)
            no.place(x=500, y=630)
            


    l1=tk.Label(root,text="Telephony Get Device ID",background="olive",font=('times', 18, ' bold '),width=25)
    l1.place(x=0,y=50)
    tele_device=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=tele_device)
    tele_device.place(x=450,y=50)

    l2=tk.Label(root,text="Telephony Get Subscriber ID",background="olive",font=('times', 18, ' bold '),width=25)
    l2.place(x=0,y=90)
    tele_subscriber=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=tele_subscriber)
    tele_subscriber.place(x=450,y=90)

    l3=tk.Label(root,text="Abort Broadcast",background="olive",font=('times', 18, ' bold '),width=15)
    l3.place(x=0,y=130)
    abort=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=abort)
    abort.place(x=450,y=130)
    
    l4=tk.Label(root,text="Send SMS",background="olive",font=('times', 18, ' bold '),width=15)
    l4.place(x=0,y=170)
    sendsms=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=sendsms)
    sendsms.place(x=450,y=170)

    l5=tk.Label(root,text="Delete Packages",background="olive",font=('times', 18, ' bold '),width=15)
    l5.place(x=0,y=210)
    delete_pack=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=delete_pack)
    delete_pack.place(x=450,y=210)

    l6=tk.Label(root,text="Phone_State",background="olive",font=('times', 18, ' bold '),width=15)
    l6.place(x=0,y=250)
    phone_s=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=phone_s)
    phone_s.place(x=450,y=250)

    l7=tk.Label(root,text="SMS_Received",background="olive",font=('times', 18, ' bold '),width=15)
    l7.place(x=0,y=290)
    sms_received=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=sms_received)
    sms_received.place(x=450,y=290)

    l8=tk.Label(root,text="Ljava.net.InetSocket Address",background="olive",font=('times', 18, ' bold '),width=25)
    l8.place(x=0,y=330)
    ljava=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=ljava)
    ljava.place(x=450,y=330)

    l9=tk.Label(root,text="Read_SMS",background="olive",font=('times', 18, ' bold '),width=10)
    l9.place(x=0,y=370)
    readsms=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=readsms)
    readsms.place(x=450,y=370)

    l10=tk.Label(root,text="Android.intent.action_Boot_completed",background="olive",font=('times',18, ' bold '),width=30)
    l10.place(x=0,y=410)
    boot_comp=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=boot_comp)
    boot_comp.place(x=450,y=410)

    l11=tk.Label(root,text="IO.File.*delete",background="olive",font=('times', 18, ' bold '),width=15)
    l11.place(x=0,y=450)
    io_delete=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=io_delete)
    io_delete.place(x=450,y=450)

    l12=tk.Label(root,text="Chown",background="olive",font=('times', 18, ' bold '),width=10)
    l12.place(x=0,y=490)
    chown=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=chown)
    chown.place(x=450,y=490)

    l13=tk.Label(root,text="Chmod",background="olive",font=('times', 18, ' bold '),width=10)
    l13.place(x=600,y=50)
    chmod=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=chmod)
    chmod.place(x=1050,y=50)


    l14=tk.Label(root,text="Mount",background="olive",font=('times', 18, ' bold '),width=10)
    l14.place(x=600,y=90)
    mount=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=mount)
    mount.place(x=1050,y=90)

    l15=tk.Label(root,text=".APK",background="olive",font=('times', 18, ' bold '),width=10)
    l15.place(x=600,y=130)
    apk=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=apk)
    apk.place(x=1050,y=130)

    l16=tk.Label(root,text=".ZIP",background="olive",font=('times', 18, ' bold '),width=10)
    l16.place(x=600,y=170)
    zip_file=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=zip_file)
    zip_file.place(x=1050,y=170)

    l17=tk.Label(root,text=".DEX",background="olive",font=('times', 18, ' bold '),width=10)
    l17.place(x=600,y=210)
    dex_file=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=dex_file)
    dex_file.place(x=1050,y=210)

    l18=tk.Label(root,text="Camera",background="olive",font=('times', 18, ' bold '),width=10)
    l18.place(x=600,y=250)
    camera=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=camera)
    camera.place(x=1050,y=250)
    
    l19=tk.Label(root,text="Access_fine_location",background="olive",font=('times', 18, ' bold '),width=15)
    l19.place(x=600,y=290)
    access=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=access)
    access.place(x=1050,y=290)

    l20=tk.Label(root,text="install_packages",background="olive",font=('times', 18, ' bold '),width=15)
    l20.place(x=600,y=330)
    package=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=package)
    package.place(x=1050,y=330)

    l21=tk.Label(root,text="Android.intent.action.Battery_low",background="olive",font=('times', 18, ' bold '),width=25)
    l21.place(x=600,y=370)
    battery_low=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=battery_low)
    battery_low.place(x=1050,y=370)

    l22=tk.Label(root,text=".SO",background="olive",font=('times', 18, ' bold '),width=10)
    l22.place(x=600,y=410)
    so_file=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=so_file)
    so_file.place(x=1050,y=410)

    l23=tk.Label(root,text="Android.intent.action.power_connected",background="olive",font=('times', 18, ' bold '),width=30)
    l23.place(x=600,y=450)
    power_connec=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=power_connec)
    power_connec.place(x=1050,y=450)
    
    l24=tk.Label(root,text="System.* Load Library",background="olive",font=('times', 18, ' bold '),width=30)
    l24.place(x=600,y=490)
    load_lib=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=load_lib)
    load_lib.place(x=1050,y=490)

    l25=tk.Label(root,text=".EXE",background="olive",font=('times', 18, ' bold '),width=10)
    l25.place(x=600,y=530)
    exe_file=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=exe_file)
    exe_file.place(x=1050,y=530)
    def window():
        root.destroy()

    fetchText=tk.Entry(root,bd=2,width=5,font=("TkDefaultFont", 20),textvar=index_var)
    fetchText.place(x=1150,y=70)
    fetchbtn = tk.Button(root,text="Fetch",command=fetchData,font=('times', 15, ' bold '),width=10,height="1",bg="green")
    fetchbtn.place(x=1150,y=110)
    
        
    button1 = tk.Button(root,text="Submit",command=Detect,font=('times', 15, ' bold '),width=10,height="1",bg="green")
    button1.place(x=1150,y=160)
    
    button5 = tk.Button(root, text="Exit", command=window, width=10, height=1, font=('times', 15, ' bold '),bg="red",fg="white")
    button5.place(x=1150, y=200)
   
    root.mainloop()

Train()