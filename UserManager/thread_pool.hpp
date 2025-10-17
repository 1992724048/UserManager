#pragma once
#include <future>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <tbb/task_arena.h>
#include <tbb/task_group.h>

namespace tp {
    /**
     * @brief 支持任务窃取, 自动分配线程资源和负载
    */
    class ThreadPool {
    public:
        /**
         * @brief 构造函数，初始化线程池
         *
         * @param num_threads 线程池中线程的数量，默认为硬件支持的并发数
         */
        explicit ThreadPool(const int num_threads = std::thread::hardware_concurrency()) : arena_(num_threads), task_count_(0) {}

        /**
         * @brief 获取线程池中线程的最大数量
         *
         * @return int 线程池中线程的最大数量
         */
        auto max_threads() const -> int {
            return arena_.max_concurrency();
        }

        /**
         * @brief 提交一个任务到线程池
         *
         * @tparam F 任务函数类型
         * @tparam Args 任务函数参数类型
         * @param f 任务函数
         * @param args 任务函数的参数
         * @return std::future<std::invoke_result_t<F, Args...>> 任务的返回值的future对象
         */
        template<typename F, typename... Args>
        auto push(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>> {
            using ResultType = std::invoke_result_t<F, Args...>;

            auto task_ptr = std::make_shared<std::packaged_task<ResultType()>>([func = std::forward<F>(f), args_tuple = std::make_tuple(std::forward<Args>(args)...)]()mutable {
                return std::apply([&func]<typename... T>(T&&... args) -> ResultType {
                                      return std::invoke(func, std::forward<T>(args)...);
                                  },
                                  std::move(args_tuple));
            });

            std::future<ResultType> res = task_ptr->get_future();

            task_count_.fetch_add(1, std::memory_order_relaxed);

            arena_.enqueue([this, task_ptr]() {
                group_.run([this, task_ptr] {
                    (*task_ptr)();
                    task_count_.fetch_sub(1, std::memory_order_relaxed);
                    {
                        std::lock_guard lock(mtx_);
                        cv_.notify_all();
                    }
                });
            });

            return res;
        }

        /**
         * @brief 等待所有任务完成
         */
        auto wait() -> void {
            std::unique_lock lock(mtx_);
            cv_.wait(lock,
                     [this] {
                         return task_count_.load(std::memory_order_relaxed) == 0;
                     });
        }

        /**
         * @brief 等待所有任务完成，或者等待指定时间后返回
         *
         * @tparam Rep 持续时间的表示类型
         * @tparam Period 持续时间的周期类型
         * @param duration 等待的时间
         * @return bool 如果所有任务完成则返回true，否则返回false
         */
        template<typename Rep, typename Period>
        auto wait_for(const std::chrono::duration<Rep, Period>& duration) -> bool {
            std::unique_lock lock(mtx_);
            return cv_.wait_for(lock,
                                duration,
                                [this] {
                                    return task_count_.load(std::memory_order_relaxed) == 0;
                                });
        }

        /**
         * @brief 提交一个循环任务到线程池
         *
         * @tparam F 任务函数类型
         * @param count 循环次数
         * @param f 任务函数
         * @return std::vector<std::future<std::invoke_result_t<F, std::size_t>>> 所有任务的返回值的future对象的向量
         */
        template<typename F>
        auto push_loop(std::size_t count, F&& f) -> std::vector<std::future<std::invoke_result_t<F, std::size_t>>> {
            using ResultType = std::invoke_result_t<F, std::size_t>;
            std::vector<std::future<ResultType>> futures;
            futures.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                futures.push_back(push(std::forward<F>(f), i));
            }
            return futures;
        }

        /**
         * @brief 提交一个迭代器范围内的任务到线程池
         *
         * @tparam Iterator 迭代器类型
         * @tparam F 任务函数类型
         * @param begin 迭代器范围的起始位置
         * @param end 迭代器范围的结束位置
         * @param f 任务函数
         * @return std::vector<std::future<std::invoke_result_t<F, typename std::iterator_traits<Iterator>::value_type>>> 所有任务的返回值的future对象的向量
         */
        template<typename Iterator, typename F>
        auto push_loop(Iterator begin, Iterator end, F&& f) -> std::vector<std::future<std::invoke_result_t<F, typename std::iterator_traits<Iterator>::value_type>>> {
            using value_type = typename std::iterator_traits<Iterator>::value_type;
            using ResultType = std::invoke_result_t<F, value_type>;
            std::vector<std::future<ResultType>> futures;
            for (auto it = begin; it != end; ++it) {
                futures.push_back(push(std::forward<F>(f), *it));
            }
            return futures;
        }

    private:
        tbb::task_arena arena_;
        tbb::task_group group_;
        std::atomic<size_t> task_count_;
        std::mutex mtx_;
        std::condition_variable cv_;
    };

    /**
     * @brief 时间守护结构体，用于记录和计算时间持续
     */
    struct TimeGuard {
        /**
         * @brief 使用std::chrono::steady_clock作为时钟
         */
        using Clock = std::chrono::steady_clock;
        /**
         * @brief 时间点类型
         */
        using TimePoint = Clock::time_point;

        /**
         * @brief 构造函数，初始化时间守护并记录起始时间
         */
        TimeGuard() : start(Clock::now()) {}

        /**
         * @brief 更新起始时间点为当前时间
         */
        auto update_start() -> void {
            start = Clock::now();
        }

        /**
         * @brief 获取从起始时间点到当前时间点的持续时间，以秒为单位
         *
         * @return double 持续时间，单位为秒
         */
        [[nodiscard]] auto get_duration() const -> double {
            return std::chrono::duration<double>(Clock::now() - start).count();
        }

    private:
        /**
         * @brief 起始时间点
         */
        TimePoint start;
    };
}
