/* phy@bitnp.net */
if(window.Vue){
    Vue.component('comp-importer', {
        props: {userList: Array},
        data: function(){return {
            importByGroupPath: '',
            importByListText: sessionStorage['groupbatch_importByListText'] || '',
        }},
        watch: {
            importByListText: function(newValue){
                sessionStorage['groupbatch_importByListText'] = newValue;
            }
        },
        mounted: function(){
            // switch tab
            if (sessionStorage['groupbatch_importByListText']){
                jQuery(this.$refs['import-tabs-by-list']).tab('show');
            }
        },
        methods: {
            importByGroup: function (event) {
                if(event) event.preventDefault();
                alert(this.importByGroupPath);
            },
            importByList: function (event) {
                if(event) event.preventDefault();
                var addItem = this.addItem;
                this.importByListText.split("\n").forEach(function(v){
                    var inp = v.trim();
                    if (inp != '') {
                        addItem({username: inp});
                    }
                    // if (inp.indexOf('@') >= 0){
                    //     addItem({email: inp});
                    // }else{
                    // }
                });
                this.importByListText = '';
            },
            addItem: function (item) {
                if (item.opState == undefined){
                    item.opState = 0;
                }
                // TODO: duplicate elimination
                this.userList.push(item);
            }
        }
    });
    Vue.component('comp-list', {
        props: {userList: Array},
        template: '#comp-list-template',
        methods: {
            removeItem: function(index){
                this.userList.splice(index, 1);
            },
            loadItemMeta: function(index){
                Vue.set(this.userList[index], 'errorMessage', 'DEV');
            }
        }
    });
    Vue.component('comp-list-item', {
        props: {username: String, email: String, opState: Number, enabled: String, errorMessage: String, name: String, createdTimestamp: String, index: Number},
        template: '#comp-list-item-template',
        methods: {
            loadMeta: function(){
                this.errorMessage = 'Dev';
            }
        }
    });
    Vue.component('comp-target', {
        props: {userList: Array, targetPath: String},
        data: function(){return {
            operation: 'add',
            userListPending: [],
            processor: 0,
            // targetPath: this.initialTargetPath || '',
        };},
        computed: {
            pendingCount: function(){
                return this.userListPending.length;
            },
            doneCount: function(){
                return this.userList.length - this.pendingCount;
            },
        },
        watch: {
            operation: {
                handler: function(newv, oldv){
                    this.watchUserList();
                },
            },
            userList: {
                deep: true,
                handler: function(newv, oldv){
                    this.watchUserList();
                },
            },
        },
        methods: {
            watchUserList: function(){
                this.userListPending = this.userList.filter(this.getUserListPendingFilter());
            },
            getUserListPendingFilter: function(){
                if (this.operation == 'add') {
                    return function(item){
                        return item.opState != 1;
                    };
                }
                if (this.operation == 'remove') {
                    return function(item){
                        return item.opState != -1;
                    };
                }
                return function(item){
                    return item.opState == 0;
                };
            },
            execute: function (event) {
                if(event) event.preventDefault();
                alert(this.targetPath);
            },
            clearDone: function (event) {
                if(event) event.preventDefault();
                var filt = this.getUserListPendingFilter();
                this.$emit('update:userList', this.userList.filter(filt));
            }
        }
    });
    var view = new Vue({
        el: '#app',
        data: {
            userList: [],
            // targetPath: '',
        }
    });
}