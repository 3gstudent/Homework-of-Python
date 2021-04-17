
from tkinter import *
from tkinter import ttk, filedialog
import os
from xml.dom import minidom

class Application_UI(object):
    
    path = os.path.abspath(".")
    scroll_visiblity = True
    
    font = 11
    font_type = "Courier New"
    
    def __init__(self):
        window = Tk()
        self.root = window
        win_width = 800
        win_height = 600
        
        screen_width, screen_height = window.maxsize() 
        x = int((screen_width - win_width) / 2)
        y = int((screen_height - win_height) / 2)
        window.title("Exchange EWS XML Parser")
        window.geometry("%sx%s+%s+%s" % (win_width, win_height, x, y))
        
        menu = Menu(window)
        window.config(menu = menu)
        
        selct_path = Menu(menu, tearoff = 0)
        selct_path.add_command(label = "Open folder", command = self.open_dir)
        selct_path.add_command(label = "Quit", command=window.quit) 
        
        menu.add_cascade(label = "File", menu = selct_path)
        
        about = Menu(menu, tearoff = 0)
        about.add_command(label = "Author", accelerator = "3gstudent")
        about.add_command(label = "Reference", accelerator = "https://github.com/yangsphp/file-manager-mask")
        about.add_command(label = "Version", accelerator = "v1.0.0")        
        menu.add_cascade(label = "About", menu = about)
        
        top_frame = Frame(window, bg = "#fff")
        top_frame.pack(side = TOP, fill = X)
        label = Label(top_frame, text = "Current path:", bg = "#fff")
        label.pack(side = LEFT)
        
        self.path_var = StringVar()
        self.path_var.set("")
        label_path = Label(top_frame, textvariable = self.path_var, bg = "#fff", fg = "red", height = 2)
        label_path.pack(anchor = W)
              
        paned_window = PanedWindow(window, showhandle = False, orient=HORIZONTAL)
        paned_window.pack(expand = 1, fill = BOTH)
        
        self.left_frame = Frame(paned_window)
        paned_window.add(self.left_frame)
        
        self.tree = ttk.Treeview(self.left_frame, show = "tree", selectmode = "browse")
        tree_y_scroll_bar = Scrollbar(self.left_frame, command = self.tree.yview, relief = SUNKEN, width = 2)
        tree_y_scroll_bar.pack(side = RIGHT, fill = Y)
        self.tree.config(yscrollcommand = tree_y_scroll_bar.set)
        self.tree.pack(expand = 1, fill = BOTH)
        
        right_frame = Frame(paned_window)
        paned_window.add(right_frame)
        
        right_top_frame = Frame(right_frame)
        right_top_frame.pack(expand = 1, fill = BOTH)
        
        self.number_line = Text(right_top_frame, width = 0, takefocus = 0, border = 0, font = (self.font_type, self.font), cursor = "") 
        self.number_line.pack(side = LEFT, fill = Y)
        
        text = Text(right_top_frame, font = (self.font_type, self.font), state = DISABLED, cursor = "", wrap = NONE)
        self.text_obj = text
        text_x_scroll = Scrollbar(right_frame, command = text.xview, orient = HORIZONTAL)
        text_y_scroll = Scrollbar(right_top_frame, command = text.yview)
        self.text_scroll_obj = text_y_scroll
        text.config(xscrollcommand = text_x_scroll.set, yscrollcommand = text_y_scroll.set)
        text_y_scroll.pack(side = RIGHT, fill = Y)
        text_x_scroll.pack(side = BOTTOM, fill = X)
        text.pack(expand = 1, fill = BOTH)
        
        right_bottom_frame = Frame(right_frame)
        right_bottom_frame.pack(side = BOTTOM, fill = X)
        
        self.load_tree("", self.path)
        self.tree.bind("<<TreeviewSelect>>", lambda event: self.select_tree())
        text.bind("<MouseWheel>", lambda event : self.update_line())
        
        self.number_line.bind("<FocusIn>", self.focus_in_event)
        self.number_line.bind('<Button-1>', self.button_ignore)
        self.number_line.bind('<Button-2>', self.button_ignore)
        self.number_line.bind('<Button-3>', self.button_ignore)
        self.number_line.bind('<B1-Motion>', self.button_ignore)
        self.number_line.bind('<B2-Motion>', self.button_ignore)
        self.number_line.bind('<B3-Motion>', self.button_ignore)
        
        self.text_scroll_obj.bind('<B1-Motion>', lambda event: self.update_line())
        self.text_obj.bind('<KeyRelease>', lambda event: self.update_line())
        
        text.bind("<Control-Key-Z>", lambda event: self.toUndo())
        text.bind("<Control-Key-Y>", lambda event: self.toRedo())
        
        window.mainloop()

class Application(Application_UI):
    def __init__(self):
        Application_UI.__init__(self)
    
            
    def open_dir(self):
        path = filedialog.askdirectory(title = u"Set path", initialdir = self.path)
        print("Open:"+path)
        self.path_var.set(path)
        self.path = path
        self.delete_tree()
        self.load_tree("", self.path)
    

    def is_file(self, path):
        if os.path.isfile(path):
           return True
        return False

    
    def delete_tree(self):
        self.tree.delete(self.tree.get_children())

    
    def focus_in_event(self, event=None):
        self.text_obj.focus_set()

    
    def button_ignore(self, ev=None):
        return "break"
    

    def load_tree(self, root, path):
        is_open = False
        if root == "":
            is_open = True
        
        root = self.tree.insert(root, END, text = " " + self.dir_name(path), values = (path,), open = is_open)    
        
        try:
            for file in os.listdir(path):
                file_path = path + "\\" + file
                
                if os.path.isdir(file_path):
                    self.load_tree(root, file_path)
                else:
                    self.tree.insert(root, END, text = " " + file, values = (file_path,))
        except Exception as e:
            print(e)

            
    def file_extension(self, file):
        file_info = os.path.splitext(file)
        return file_info[-1]

    
    def dir_name(self, path):
        path_list = os.path.split(path)
        return path_list[-1]
    

    def update_line(self):
        if not self.scroll_visiblity:
            return 
        self.number_line.delete(1.0, END)
        text_h, text_l = map(int, str.split(self.text_obj.index(END), "."))
        q = range(1, text_h)
        r = map(lambda x: '%i' % x, q)
        s = '\n'.join(r)
        self.number_line.insert(END, s)
        
        if text_h <= 100:
            width = 2
        elif text_h <= 1000:
            width = 3
        elif text_h <= 10000:
            width = 4
        else:
            width = 5
        self.number_line.configure(width = width)
        self.number_line.yview_moveto(self.text_obj.yview()[0])
        

    def select_tree(self):
        for item in self.tree.selection():
            item_text = self.tree.item(item, "values")
            select_path = "\\".join(item_text)
            self.path_var.set(select_path)
            
            self.text_obj.config(state = NORMAL, cursor = "xterm")            
            self.text_obj.delete(1.0, END)
            self.text_obj.configure(fg='black')
            self.update_line()
            if self.is_file(select_path) is True:
                try:
                    ext = self.file_extension(select_path)
                    if ext == ".xml":
                        self.open__soap_xml(select_path, "r", "utf-8")
                    else:
                        self.open_file(select_path, "r", "utf-8")
                    self.update_line()
                except Exception as e:
                    print(e)
            else:
                self.text_obj.config(state = DISABLED, cursor = "")

                
    def open_file(self, select_path, mode, encoding = None):
        with open(select_path, mode = mode, encoding = encoding) as f:
            self.text_obj.insert(1.0, f.read())


    def open__soap_xml(self, select_path, mode, encoding = None):
        with open(select_path, mode = mode, encoding = encoding) as f:
            data = f.read()
            try:
                dom = minidom.parse(select_path)               
                collection = dom.documentElement

                #ResponseMessage
                data_response = dom.getElementsByTagName("m:GetItemResponseMessage")
                if(data_response[0].getAttribute("ResponseClass") != "Success"):
                    self.text_obj.configure(fg='red')
                    self.text_obj.insert(1.0, "[!]Wrong data,size: " + str(len(data)))                    
                    return
                #Subject
                if collection.hasAttribute("t:Subject"):
                    data_subject = dom.getElementsByTagName("t:Subject")
                    self.text_obj.insert(1.0, "Subject : " + data_subject[0].firstChild.data + "\n")
                else:
                    self.text_obj.insert(1.0, "Subject : \n")           
                #Sender
                data_from = dom.getElementsByTagName("t:Sender")
                output_from = "From    : " + data_from[0].getElementsByTagName("t:Name")[0].firstChild.data + "<" + data_from[0].getElementsByTagName("t:EmailAddress")[0].firstChild.data + "> \n"
                self.text_obj.insert(2.0, output_from)
                #ToRecipients
                output_to = "To      : "
                if dom.getElementsByTagName("t:ToRecipients"):
                    data_to = dom.getElementsByTagName("t:ToRecipients")
                    data_to_mailbox = data_to[0].getElementsByTagName("t:Mailbox")
                    for i in range(len(data_to_mailbox)):
                        output_to = output_to + data_to_mailbox[i].getElementsByTagName("t:Name")[0].firstChild.data + "<" + data_to_mailbox[i].getElementsByTagName("t:EmailAddress")[0].firstChild.data + ">,"                     
                self.text_obj.insert(3.0, output_to[:-1] + "\n")
                #CcRecipients
                output_cc = "Cc      : "
                if dom.getElementsByTagName("t:CcRecipients"):
                    data_cc = dom.getElementsByTagName("t:CcRecipients")
                    data_cc_mailbox = data_cc[0].getElementsByTagName("t:Mailbox")
                    for i in range(len(data_cc_mailbox)):
                        output_cc = output_cc + data_cc_mailbox[i].getElementsByTagName("t:Name")[0].firstChild.data + "<" + data_cc_mailbox[i].getElementsByTagName("t:EmailAddress")[0].firstChild.data + ">,"                             
                self.text_obj.insert(4.0, output_cc[:-1] + "\n")
                #DateTimeReceived
                if dom.getElementsByTagName("t:DateTimeReceived"):
                    data_time = dom.getElementsByTagName("t:DateTimeReceived")
                    self.text_obj.insert(5.0, "Received: " + data_time[0].firstChild.data + "\n")
                else:
                    self.text_obj.insert(5.0, "Received: \n")                     
                self.text_obj.insert(6.0, "----------------------------------------------------------------------------------------------------\n")
                #FileAttachment
                output_attachment = ""
                if dom.getElementsByTagName("t:FileAttachment"):                    
                    data_attachment = dom.getElementsByTagName("t:FileAttachment")
                    for i in range(len(data_attachment)):
                        output_attachment = output_attachment + "Attachment: " + data_attachment[i].getElementsByTagName("t:Name")[0].firstChild.data + "\n"                       
                    output_attachment = output_attachment + "----------------------------------------------------------------------------------------------------\n"
                self.text_obj.insert(7.0, output_attachment)
                #Body          
                data_body = dom.getElementsByTagName("t:Body")                
                if data_body:                    
                    self.text_obj.insert(END, data_body[0].firstChild.data)   
            except Exception as e:
                print(select_path + ":" + str(e))                   


if __name__ == "__main__":
    Application()
