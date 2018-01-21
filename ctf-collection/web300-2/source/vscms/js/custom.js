$(function(){
        $('[data-toggle="tooltip"]').tooltip();
        
        $(".divlink, .nlink").live("click", function() {
		var href = $(this).attr('href');
                if(href != '')
                   $.gotoUrl(href);
                return false;
	});
});
