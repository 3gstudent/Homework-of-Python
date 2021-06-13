#python3
import os
import sys
import re
import requests
from pyVmomi import vmodl, vim
from pyVim.connect import SmartConnect, Disconnect
import warnings
warnings.filterwarnings("ignore")


def print_vm_info(virtual_machine):
    summary = virtual_machine.summary
    print("Name       : ", summary.config.name)
    print("Template   : ", summary.config.template)
    print("Path       : ", summary.config.vmPathName)
    print("Guest      : ", summary.config.guestFullName)
    print("Instance UUID : ", summary.config.instanceUuid)
    print("Bios UUID     : ", summary.config.uuid)
    annotation = summary.config.annotation
    if annotation:
        print("Annotation : ", annotation)
    print("State      : ", summary.runtime.powerState)
    if summary.guest is not None:
        ip_address = summary.guest.ipAddress
        tools_version = summary.guest.toolsStatus
        if tools_version is not None:
            print("VMware-tools: ", tools_version)
        else:
            print("Vmware-tools: None")
        if ip_address:
            print("IP         : ", ip_address)
        else:
            print("IP         : None")
    if summary.runtime.question is not None:
        print("Question  : ", summary.runtime.question.text)
    print("")


def search_for_obj(content, vim_type, name, folder=None, recurse=True):
    """
    Search the managed object for the name and type specified
    Sample Usage:
    get_obj(content, [vim.Datastore], "Datastore Name")
    """
    if folder is None:
        folder = content.rootFolder

    obj = None
    container = content.viewManager.CreateContainerView(folder, vim_type, recurse)

    for managed_object_ref in container.view:
        if managed_object_ref.name == name:
            obj = managed_object_ref
            break
    container.Destroy()
    return obj


def get_obj(content, vim_type, name, folder=None, recurse=True):
    """
    Retrieves the managed object for the name and type specified
    Throws an exception if of not found.
    Sample Usage:
    get_obj(content, [vim.Datastore], "Datastore Name")
    """
    obj = search_for_obj(content, vim_type, name, folder, recurse)
    if not obj:
        raise RuntimeError("Managed Object " + name + " not found.")
    return obj


def List_VM(api_host, username, password):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)

    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    try:
        content = service_instance.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive)

        children = container_view.view
        for child in children:
            print_vm_info(child)
            
    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def Get_VM(api_host, username, password, vm_name):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)

    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    try:
        content = service_instance.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive)

        children = container_view.view
        pat = re.compile(vm_name, re.IGNORECASE)
        for child in children:
            if pat.search(child.summary.config.name) is not None:
                    print_vm_info(child)
            
    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def List_Host(api_host, username, password):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)

    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    try:
        content = service_instance.RetrieveContent()

        container = content.rootFolder  # starting point to look into
        view_type = [vim.HostSystem]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive)

        children = container_view.view
        for child in children:
            #print(child.summary)
            print(" -  host:" + str(child.summary.host))
            print("    name:" + child.summary.config.name)
            print("    connection_state:" + child.summary.runtime.connectionState)
            print("    power_state:" + child.summary.runtime.powerState)

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def ListVMProcess(api_host, username, password, vm_name, guest_username, guest_user_password):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")
    creds = vim.vm.guest.NamePasswordAuthentication(username=guest_username, password=guest_user_password)

    try:
        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")
        profile_manager = content.guestOperationsManager.processManager
        res = profile_manager.ListProcessesInGuest(vm, creds)
        for i in res:
            print(" -  name:" + i.name)
            print("    cmdLine:" + i.cmdLine)
            print("    pid:" + str(i.pid))
            print("    owner:" + i.owner)
            print("    startTime:" + str(i.startTime)) 
     
    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def CreateVMProcess(api_host, username, password, vm_name, guest_username, guest_user_password, path, arguments):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    creds = vim.vm.guest.NamePasswordAuthentication(username = guest_username, password = guest_user_password)

    program_spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath = path, arguments = arguments)

    try:
        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")
        profile_manager = content.guestOperationsManager.processManager
        res = profile_manager.StartProgramInGuest(vm, creds, program_spec)
        print("[+] Process Pid:" + str(res))

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def KillVMProcess(api_host, username, password, vm_name, guest_username, guest_user_password, pid):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    creds = vim.vm.guest.NamePasswordAuthentication(username = guest_username, password = guest_user_password)

    try:
        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")
        profile_manager = content.guestOperationsManager.processManager

        res = profile_manager.TerminateProcessInGuest(vm, creds, int(pid))
        if res == None:
            print("[+] Kill process success")
        else:
            print(res)

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def ListVMFolder(api_host, username, password, vm_name, guest_username, guest_user_password, path):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    creds = vim.vm.guest.NamePasswordAuthentication(username = guest_username, password = guest_user_password)

    try:
        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")

        profile_manager = content.guestOperationsManager.fileManager

        res = profile_manager.ListFilesInGuest(vm, creds, path)
        for i in res.files:
            print(" -  path:" + i.path)
            print("    size:" + str(i.size))
            print("    type:" + i.type)

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def DeleteVMFile(api_host, username, password, vm_name, guest_username, guest_user_password, path):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    creds = vim.vm.guest.NamePasswordAuthentication(username = guest_username, password = guest_user_password)

    try:
        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")

        profile_manager = content.guestOperationsManager.fileManager

        res = profile_manager.DeleteFileInGuest(vm, creds, path)
        if res == None:
            print("[+] Delete file success")
        else:
            print(res)

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def DownloadFileFromVM(api_host, username, password, vm_name, guest_username, guest_user_password, guest_path, type):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    creds = vim.vm.guest.NamePasswordAuthentication(username = guest_username, password = guest_user_password)

    try:

        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")
   
        profile_manager = content.guestOperationsManager.fileManager
        res = profile_manager.InitiateFileTransferFromGuest(vm, creds, guest_path)      
        print("[+] transfer uri: " + res.url)
        print("    size: " + str(res.size))
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        } 
        r = requests.get(res.url, headers = headers, verify = False)
        if r.status_code ==200:
            if type == "text":
                print("[+] result: ")
                print(r.text)
            else:
                print("[+] save the result as temp.bin")
                with open("temp.bin", "wb") as file_obj:
                    file_obj.write(r.content)
  
        else:         
            print("[!]" + str(r.status_code))
            print(r.text)
            exit(0)

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


def UploadFileToVM(api_host, username, password, vm_name, guest_username, guest_user_password, local_path, guest_path):
    service_instance = SmartConnect(host=api_host, user=username, pwd=password, port=443, disableSslCertValidation=True)
    if not service_instance:
        raise SystemExit("[!] Unable to connect to host with supplied credentials.")

    creds = vim.vm.guest.NamePasswordAuthentication(username = guest_username, password = guest_user_password)

    with open(local_path, 'rb') as file_obj:
        data_to_send = file_obj.read()

    try:

        content = service_instance.RetrieveContent()
        vm = get_obj(content, [vim.VirtualMachine], vm_name)
        if not vm:
            raise SystemExit("Unable to locate the virtual machine.")

        file_attribute = vim.vm.guest.FileManager.FileAttributes()    
        profile_manager = content.guestOperationsManager.fileManager
        res = profile_manager.InitiateFileTransferToGuest(vm, creds, guest_path, file_attribute, len(data_to_send), True)      
        print("[+] transfer uri: " + res)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        } 
        r = requests.put(res, headers = headers, data = data_to_send, verify = False)
        if r.status_code ==200:
            print("[+] " + r.text)
        else:         
            print("[!]" + str(r.status_code))
            print(r.text)
            exit(0)

    except vmodl.MethodFault as error:
        print("[!] Caught vmodl fault : " + error.msg)


if __name__ == "__main__":

    if len(sys.argv)!=5:
        print("vSphereWebServicesAPI_Manage.py")
        print("Use vSphere Web Services API to manage the VM")
        print("Reference: https://github.com/vmware/pyvmomi/")
        print("Install: pip install --upgrade pyvmomi")       
        print("Usage:")
        print("%s <vCenter IP> <vCenter user> <vCenter password> <mode>"%(sys.argv[0]))
        print("mode:")
        print("- ListVM")        
        print("- GetVMConfig")
        print("- List_Host")
        print("- ListVMProcess")
        print("- CreateVMProcess")
        print("- KillVMProcess")
        print("- ListVMFolder")        
        print("- DeleteVMFile")        
        print("- DownloadFileFromVM") 
        print("- UploadFileToVM") 
        print("Eg.")
        print("%s 192.168.1.1 administrator@vsphere.local 123456 ListVM"%(sys.argv[0]))      
        sys.exit(0)
    else:

        if sys.argv[4] == "ListVM":  
            print("[*] Try to list the VM")
            List_VM(sys.argv[1], sys.argv[2], sys.argv[3])

        elif sys.argv[4] == "ListHost":  
            print("[*] Try to list the Host")
            List_Host(sys.argv[1], sys.argv[2], sys.argv[3])

        elif sys.argv[4] == "GetVMConfig":  
            print("[*] Try to get the config of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            Get_VM(sys.argv[1], sys.argv[2], sys.argv[3], vm)

        elif sys.argv[4] == "ListVMProcess": 
            print("[*] Try to list the processes of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")    
            ListVMProcess(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password)

        elif sys.argv[4] == "CreateVMProcess": 
            print("[*] Try to create the process of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            program_path = input("input the path of the program(eg:c:\\windows\\system32\\cmd.exe): ")
            program_arguments = input("input the arguments of the program(eg:/c echo 1 >c:\\1.txt): ")
            CreateVMProcess(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password, program_path, program_arguments)

        elif sys.argv[4] == "KillVMProcess": 
            print("[*] Try to kill the process of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            pid = input("input the pid: ")
            KillVMProcess(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password, pid)

        elif sys.argv[4] == "ListVMFolder": 
            print("[*] Try to list the file of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            folder_path = input("input the folder(eg: c:\\1): ")
            ListVMFolder(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password, folder_path)

        elif sys.argv[4] == "DeleteVMFile": 
            print("[*] Try to delete the file of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            file_path = input("input the file(eg: c:\\1.txt): ")
            DeleteVMFile(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password, file_path)

        elif sys.argv[4] == "DownloadFileFromVM": 
            print("[*] Try to download the file of the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            file_path = input("input the file of the VM(eg: c:\\1.txt or /tmp/1.txt): ")
            file_type = input("input the file type(text or raw): ")
            DownloadFileFromVM(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password, file_path, file_type)

        elif sys.argv[4] == "UploadFileToVM": 
            print("[*] Try to upload the file to the VM")
            vm = input("input the name of the VM(eg:Win7): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            local_file_path = input("input the local file(eg: c:\\1.txt or /tmp/1.txt): ")
            target_file_path = input("input the target file(eg: c:\\1.txt or /tmp/1.txt): ")
            UploadFileToVM(sys.argv[1], sys.argv[2], sys.argv[3], vm, guest_username, guest_user_password, local_file_path, target_file_path)

        else:
            print("[!] Wrong parameter")


