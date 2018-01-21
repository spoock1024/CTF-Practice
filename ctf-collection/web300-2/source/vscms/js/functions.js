$(function(){
        $.extend({
                escapeHtml : function(str) {
                        var entityMap = {
                                "&": "&amp;",
                                "<": "&lt;",
                                ">": "&gt;",
                                '"': '&quot;',
                                "'": '&#39;',
                                "/": '&#x2F;'
                        };
                        return String(str).replace(/[&<>"'\/]/g, function (s) {
                                return entityMap[s];
                        });
                }
	});
        
        
	
	$.extend({
		gotoUrl : function(url) {
			window.location.href = url;
		}
	});
});
