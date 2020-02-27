/* phy@bitnp.net */
if(location.search.indexOf('checkSession=1') >= 0 && window.opener){
    window.close();
}
else if(window.Vue){
    var importByGroupLimit = 100;
    var executeSleepTime = 400;
    var openLoginWindow = function(){
        window.open('?checkSession=1', 'checkSessionWindow');
    };
    var axiosGlobalCatch = function(error){
        if (error.response && error.response.status == 401) {
            alert('请刷新页面重新登录。');
            openLoginWindow();
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
            importByGroupFirst: 0,
            importByGroupProcessing: false,
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
                _this.importByGroupProcessing = true;
                axios({
                    method: 'GET',
                    url: './',
                    params: {
                        path: this.importByGroupPath,
                        first: this.importByGroupFirst,
                    },
                    headers: {'Accept': 'application/json'}
                })
                    .then(function(response){
                        response.data[0].members.forEach(function(user){
                            addItem(user);
                        });
                        if(response.data[0].members.length >= importByGroupLimit){
                            alert("本组成员较多，目前只请求了 "+importByGroupLimit+" 项结果，将为你修改表单中的数字，但你需要手动点击加载成员，继续加载成员。");
                            _this.importByGroupFirst = _this.importByGroupFirst + response.data[0].members.length;
                        }
                        if(response.data[0].members.length == 0){
                            alert('你的请求条件下没有返回结果。这通常表示你不需要继续加载成员，或数字设置得过大。');
                        }
                    })
                    .catch(axiosGlobalCatch)
                    .finally(function(){
                        _this.importByGroupProcessing = false;
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
                // check duplicate
                var first_dup_index = -1;
                this.userList.some(function(user, index){
                    if(user.username == item.username || user.email == item.username){
                        first_dup_index = index;
                        return true; // equivalent to break in forEach
                    }
                });
                if (first_dup_index != -1){
                    if (this.userList[first_dup_index].email == item.username){
                        // in this case userList item is loaded
                        // so we shouldn't update it with a rough item
                        return;
                    }
                    // update first occurance
                    Vue.set(this.userList, first_dup_index,
                        Object.assign({}, this.userList[first_dup_index], item));
                    return;
                }
                // init default value
                if (item.opState == undefined){
                    item.opState = 0;
                }
                item.errorMessage = '';
                item.metaLoading = false;
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
            clearError: function(index){
                this.userList[index].errorMessage = '';
            },
            loadItemMeta: function(index){
                var userList = this.userList, thisitem = userList[index];
                thisitem.metaLoading = true;
                axios({
                    method: 'GET',
                    url: '../users/',
                    params: {
                        search: thisitem.username
                    },
                    headers: {'Accept': 'application/json'}
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
                    });
            }
        }
    });
    Vue.component('comp-list-item', {
        props: {
            username: String,
            email: String,
            opState: Number,
            enabled: Boolean,
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
        props: {userList: Array, initialTargetPath: String, initialTargetInternalNote: String},
        data: function(){return {
            operation: 'compare',
            userListPending: [],
            processing: false,
            processingPromise: null,
            targetMembers: null,
            targetPath: this.initialTargetPath,
            targetInternalNote: this.initialTargetInternalNote,
        };},
        computed: {
            pendingCount: function(){
                return this.userListPending.length;
            },
        },
        watch: {
            operation: function(newv){
                this.watchUserList();
            },
            userList: {
                deep: true,
                handler: function(newv){
                    this.watchUserList();
                },
            },
            targetPath: function(newv, oldv){
                this.targetInternalNote = '';
                this.targetMembers = null;
                this.resetOpState();
            },
            processing: function(newv){
                if(newv){
                    // this is requesting a start, but it already starts
                    // we don't want multiprocessing here
                    if(this.processingPromise){
                        this.processing = false;
                        alert("正在等待未完成的操作，如需继续，请重新点击开始。");
                        return;
                    }
                    this.startNextExecution();
                }
            }
        },
        methods: {
            watchUserList: function(){
                this.userListPending = this.userList.filter(this.getUserListPendingFilter(false));
            },
            getUserListPendingFilter: function(includesError){
                if (this.operation == 'add') {
                    return function(item){
                        return item.opState != 1 && (includesError || item.errorMessage == '');
                    };
                }
                if (this.operation == 'remove') {
                    return function(item){
                        return item.opState != -1 && (includesError || item.errorMessage == '');
                    };
                }
                return function(item){
                    return item.opState == 0 && (includesError || item.errorMessage == '');
                };
            },
            toggleExecution: function (event) {
                if(event) event.preventDefault();
                this.processing = !this.processing;
            },
            clearDone: function (event) {
                if(event) event.preventDefault();
                var filt = this.getUserListPendingFilter(true); // kept items
                // Vue.set(this, 'userList', this.userList.filter(filt));
                this.$emit('update:userList', this.userList.filter(filt));
            },
            resetOpState: function (event){
                if(event) event.preventDefault();
                for(var key in this.userList){
                    Vue.set(this.userList[key], 'opState', 0);
                }
            },
            clearError: function (event) {
                if(event) event.preventDefault();
                this.userList.forEach(function(item){
                    if (item.errorMessage) Vue.set(item, 'errorMessage', '');
                });
            },
            _executionPreCheck: function (){
                if (!this.processing){
                    return false; // stopped
                }
                if (!this.userListPending.length){
                    this.processing = false;
                    return false; // no more to execute
                }
                return true;
            },
            startNextExecution: function () {
                if (!this._executionPreCheck()){
                    return; // stopped
                }
                /*
                 * Find next item first:
                 * after the item is done, it must
                 * - change opState, or
                 * - set errorMessage
                 */
                var user = this.userListPending[0];
                if (this.operation == 'add') {
                    return this._executeAdd(user);
                }
                if (this.operation == 'remove') {
                    return this._executeRemove(user);
                }
                if (this.operation == 'compare') {
                    return this._executeCompare(user);
                }
                user.errorMessage = 'NotImplemented';
                return this.sleepAndStartNextExecution();
            },
            _executeError: function(error, user){
                // parent variable: user
                if (error.response && error.response.status == 401) {
                    Vue.set(user, 'errorMessage', '请刷新页面重新登录');
                    openLoginWindow();
                    // alert('请刷新页面重新登录。');
                    return;
                }
                if (error.response) {
                    // The request was made and the server responded with a status code
                    // that falls out of the range of 2xx
                    Vue.set(user, 'errorMessage', error.response.status+': '+JSON.stringify(error.response.data));
                } else {
                    // Something happened in setting up the request that triggered an Error
                    Vue.set(user, 'errorMessage', error.message);
                }
            },
            _executeAdd: function(user){
                var _this = this;
                var reqData = 'path='+encodeURIComponent(this.targetPath)+'&username='+encodeURIComponent(user.username);
                this.processingPromise = axios({
                    method: 'POST',
                    url: './member-add',
                    headers: { 'content-type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'},
                    data: reqData,
                })
                    .then(function(response){
                        for (var key in response.data){
                            Vue.set(user, key, response.data[key]); // update with meta
                        }
                        Vue.set(user, 'opState', 1);
                    })
                    .catch(function(error){return _this._executeError(error, user);})
                    .finally(function(){
                        _this.sleepAndStartNextExecution();
                    });
            },
            _executeRemove: function(user){
                var _this = this;
                var reqData = 'path='+encodeURIComponent(this.targetPath)+'&username='+encodeURIComponent(user.username);
                this.processingPromise = axios({
                    method: 'POST',
                    url: './member-remove',
                    headers: { 'content-type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'},
                    data: reqData,
                })
                    .then(function(response){
                        for (var key in response.data){
                            Vue.set(user, key, response.data[key]); // update with meta
                        }
                        Vue.set(user, 'opState', -1);
                    })
                    .catch(function(error){return _this._executeError(error, user);})
                    .finally(function(){
                        _this.sleepAndStartNextExecution();
                    });
            },
            _executeCompare: function(user){
                var _this = this;
                // check against MemberList
                var compare = function(){
                    if(!_this.processing){
                        _this.processingPromise = null;
                        return; // may be set by compareFetch
                    }
                    if(
                        _this.targetMembers.some(function(item){
                            if(item.username == user.username || item.email == user.username){
                                if(user.enabled == undefined){
                                    // update user with meta
                                    for (var key in item){
                                        Vue.set(user, key, item[key]);
                                    }
                                }
                                return true;
                            }
                            return false;
                        })
                    ){
                        Vue.set(user, 'opState', 1);
                    }else{
                        Vue.set(user, 'opState', -1);
                    }

                    _this.sleepAndStartNextExecution();
                };
                // fetch MemberList if not present, with auto paging
                if (this.targetMembers == null){
                    this.processingPromise = this._executeCompareFetchPromise(0)
                        .then(compare);
                }else{
                    this.processingPromise = true;
                    compare();
                }
            },
            _executeCompareFetchPromise: function(first){
                var _this = this;
                var fetch_then = function(response){
                    if (_this.targetMembers == null){
                        _this.targetMembers = [];
                    }
                    _this.targetMembers.push.apply(_this.targetMembers, response.data[0].members);
                    if(response.data[0].members.length >= importByGroupLimit){
                        return _this._executeCompareFetchPromise(first+response.data[0].members.length);
                    }
                };
                return axios({
                    method: 'GET',
                    url: './',
                    params: {path: this.targetPath, first: first},
                    headers: {'Accept': 'application/json'},
                })
                    .then(fetch_then)
                    .catch(function(error){
                        // exit
                        _this.processingPromise = null;
                        _this.processing = false;
                        axiosGlobalCatch(error);
                    });
            },
            sleepAndStartNextExecution: function(){
                var _this = this;
                _this.processingPromise = null;
                return _this.$nextTick(function(){
                    // prevent UI from showing -1
                    if (_this._executionPreCheck()){
                        setTimeout(function(){_this.startNextExecution();}, executeSleepTime);
                    }
                });
            }
        }
    });
    var view = new Vue({
        el: '#app',
        data: {
            userList: [],
            initialTargetPath: '',
            initialTargetInternalNote: '',
        },
        mounted: function(){
            this.initialTargetPath = this.$el.dataset.targetPath;
            this.initialTargetInternalNote = this.$el.dataset.targetInternalNote;
        }
    });
}