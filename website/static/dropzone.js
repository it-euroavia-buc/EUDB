//DROPZONE JS CONFIG IS NOT SET-UP YET, MUST BE IMPLEMENTED (USES DEFAULT CONFIG)

Dropzone.options.myDropzone = {
    autoProcessQueue: false,
    uploadMultiple: true,
    parallelUploads: 10, 
    maxFiles: 10, 
    init: function() { 
        myDropzone = this;
        this.element.querySelector("button[type=submit]").addEventListener("click", function(e) {  
        e.preventDefault();
        e.stopPropagation();
        myDropzone.processQueue();
    });
  }
};