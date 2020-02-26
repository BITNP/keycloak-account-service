/* phy@bitnp.net */
if(window.Vue){
    var axiosGlobalCatch = function(error){
        if (error.response && error.response.status == 401) {
            alert('请刷新页面重新登录。');
            return;
        }
        if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            alert('请求失败 ('+error.response.status+'): '+JSON.stringify(error.response.data));
        } else {
            // Something happened in setting up the request that triggered an Error
            alert('请求失败: '+error.message);
        }
    };
    Vue.component('comp-importer', {
        props: {userList: Array},
        data: function(){return {
            importByGroupPath: '',
            importByGroupProcessing: 0,
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
                var addItem = this.addItem, _this = this;
                _this.importByGroupProcessing = 1;
                axios({
                    method: 'GET',
                    url: './',
                    params: {
                        path: this.importByGroupPath
                    }
                })
                    .then(function(response){
                        response.data[0].members.forEach(function(user){
                            addItem(user);
                        });
                    })
                    .catch(axiosGlobalCatch)
                    .finally(function(){
                        _this.importByGroupProcessing = 0;
                    });
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
                item.errorMessage = '';
                item.metaLoading = false;
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
                var userList = this.userList, thisitem = userList[index];
                thisitem.metaLoading = true;
                axios({
                    method: 'GET',
                    url: '../users/',
                    params: {
                        search: thisitem.username
                    }
                })
                    .then(function(response){
                        var cur_user = response.data[0];
                        if (response.data.length > 1){
                            // opps, this is admin
                            var fi = response.data.filter(function(user){
                                return user.username == thisitem.username || user.email == thisitem.email;
                            });
                            cur_user = fi[0];
                        }
                        if (!cur_user){
                            thisitem.errorMessage = '找不到符合条件的用户';
                            return;
                        }
                        Vue.set(userList, index, Object.assign({}, userList[index], cur_user));
                    })
                    .catch(function(error){
                        if (error.response && error.response.status == 404) {
                            thisitem.errorMessage = '找不到符合条件的用户';
                            return;
                        }
                        axiosGlobalCatch(error);
                    })
                    .finally(function(){
                        userList[index].metaLoading = false;
                        // Vue.set(userList, index, Object.assign({}, , {metaLoading: false}));
                    });
            }
        }
    });
    Vue.component('comp-list-item', {
        props: {
            username: String,
            email: String,
            opState: Number,
            enabled: String,
            name: String,
            createdTimestamp: String,
            index: Number,
            errorMessage: String,
            metaLoading: Boolean
        },
        template: '#comp-list-item-template',
        methods: {
            loadMeta: function(){
                this.errorMessage = 'Dev';
            }
        }
    });
    Vue.component('comp-target', {
        props: {userList: Array, targetPath: String, targetInternalNote: String},
        data: function(){return {
            operation: 'add',
            userListPending: [],
            processing: 0,
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
            targetPath: {
                handler: function(newv, oldv){
                    this.targetInternalNote = '';
                }
            }
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
                this.processing = !this.processing;
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