using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Common
{
    public static class ResultExtensions
    {
        /// <summary>
        /// Combine two <see cref="Result{TOk,TError}"/> values into a single value containing a value
        /// constructed from the two OK states of each <see cref="Result{TOk,TError}"/>.
        /// </summary>
        /// <remarks>
        /// Works as a logical <c>AND</c> - if both inputs are OK, the output is OK;
        /// if either input is an error, the output is an error.
        /// </remarks>
        /// <returns></returns>
        public static Result<TResultOk, TError> With<TLocalOk, TError, TOtherOk, TResultOk>(
            this Result<TLocalOk, TError> result,
            Result<TOtherOk, TError> otherResult,
            Func<TLocalOk, TOtherOk, TResultOk> okCombiner)
            where TError : ICombinable<TError>
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (otherResult == null)
            {
                throw new ArgumentNullException(nameof(otherResult));
            }

            if (okCombiner == null)
            {
                throw new ArgumentNullException(nameof(okCombiner));
            }

            return result.Match(
                fromOk: localOk => otherResult.Match(
                    fromOk: otherOk => new Result<TResultOk, TError>(okCombiner(localOk, otherOk)),
                    fromError: otherError => new Result<TResultOk, TError>(otherError)
                    ),
                fromError: localError => otherResult.Match(
                    fromOk: otherOk => new Result<TResultOk, TError>(localError),
                    fromError: otherError => new Result<TResultOk, TError>(localError.Combine(otherError))
                    )
                );
        }

        /// <summary>
        /// Combine two <see cref="Result{TOk,TError}"/> values into a single value containing a tuple
        /// </summary>
        /// <remarks>
        /// Works as a logical <c>AND</c> - if both inputs are OK, the output is OK;
        /// if either input is an error, the output is an error.
        /// </remarks>
        /// <returns></returns>
        public static Result<(TFirstOk First, TSecondOk Second), TError> With<TFirstOk, TError, TSecondOk>(
            this Result<TFirstOk, TError> first,
            Result<TSecondOk, TError> second)
            where TError : ICombinable<TError>
        {
            if (first == null)
            {
                throw new ArgumentNullException(nameof(first));
            }

            if (second == null)
            {
                throw new ArgumentNullException(nameof(second));
            }

            return first.With(second, (v1, v2) => (v1, v2));
        }

        /// <summary>
        /// Combines the error and OK values when they both have the same type
        /// (i.e. takes whichever has the value).
        /// </summary>
        public static T Merge<T>(this Result<T, T> result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            return result.Match(ok => ok, error => error);
        }

        /// <summary>
        /// Combines the error and OK values. If the <see cref="Result{TLeft,TRight}"/>
        /// has the left value, the specified function is used to convert it to the right
        /// type.
        /// </summary>
        public static TOk Merge<TOk, TError>(
            this Result<TOk, TError> result,
            Func<TError, TOk> fromError)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (fromError == null)
            {
                throw new ArgumentNullException(nameof(fromError));
            }

            return result.OnError(fromError).Merge();
        }

        /// <summary>
        /// Take an action if we have an error value
        /// </summary>
        /// <param name="result"></param>
        /// <param name="action">Action to take when we have an error value.</param>
        public static void OnError<TOk, TError>(
            this Result<TOk, TError> result,
            Action<TError> action)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            result.Match(okAction: _ => { }, errorAction: action);
        }

        /// <summary>
        /// Returns the result of a function if we have an error value
        /// </summary>
        /// <param name="result"></param>
        /// <param name="operation">Function to call if we have an error value</param>
        /// <returns></returns>
        public static Result<TOk, TNextError> OnError<TOk, TError, TNextError>(
            this Result<TOk, TError> result,
            Func<TError, TNextError> operation)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation));
            }

            return result.Match(
                fromOk: ok => new Result<TOk, TNextError>(ok),
                fromError: error => new Result<TOk, TNextError>(operation(error))
                );
        }

        /// <summary>
        /// Take an action if we have an OK value
        /// </summary>
        /// <param name="result"></param>
        /// <param name="action">Action to take when we have an OK value.</param>
        public static void OnOk<TOk, TError>(
            this Result<TOk, TError> result,
            Action<TOk> action)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            result.Match(okAction: action, errorAction: _ => { });
        }

        /// <summary>
        /// Executes a function returning a <see cref="TNextOk"/> conditionally, depending
        /// on the result of this <see cref="Result{TOk,TError}"/> instance.
        /// </summary>
        /// <typeparam name="TOk"></typeparam>
        /// <typeparam name="TError"></typeparam>
        /// <typeparam name="TNextOk">The return type of <paramref name="operation"/></typeparam>
        /// <param name="result"></param>
        /// <param name="operation">A function to execute on the value of this instance if it
        /// is successful</param>
        /// <returns>
        /// An <see cref="Errorable{TNextOk}"/> containing the result of executing <paramref name="operation"/>
        /// if the input was successful, or the errors from this instance otherwise.
        /// </returns>
        public static Result<TNextOk, TError> OnOk<TOk, TError, TNextOk>(
            this Result<TOk, TError> result,
            Func<TOk, TNextOk> operation)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation));
            }

            return result.Match(
                fromOk: ok => new Result<TNextOk, TError>(operation(ok)),
                fromError: error => new Result<TNextOk, TError>(error)
                );
        }

        /// <summary>
        /// Executes a function returning a <see cref="Result{TLeft,TNextRight}"/> conditionally, depending
        /// on the result of this <see cref="Result{TLeft,TRight}"/> instance.
        /// </summary>
        /// <typeparam name="TOk"></typeparam>
        /// <typeparam name="TError"></typeparam>
        /// <typeparam name="TNextOk">The return type of <paramref name="operation"/></typeparam>
        /// <param name="result"></param>
        /// <param name="operation">A function to execute on the value of this instance if it
        /// is successful</param>
        /// <returns>
        /// An <see cref="Result{TNextOk,TError}"/> containing the result of executing <paramref name="operation"/>
        /// if the input was successful, or the errors from this instance otherwise.
        /// </returns>
        public static Result<TNextOk, TError> OnOk<TOk, TError, TNextOk>(
            this Result<TOk, TError> result,
            Func<TOk, Result<TNextOk, TError>> operation)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation));
            }

            return result.Match(
                fromOk: operation,
                fromError: error => new Result<TNextOk, TError>(error)
                );
        }

        /// <summary>
        /// Pulls a <see cref="Task"/> out from inside an <see cref="Result{TOk,TError}"/> so that the
        /// result is awaitable.
        /// </summary>
        public static Task<Result<TOk, TError>> AsTask<TOk, TError>(this Result<Task<TOk>, TError> result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            return result
                .OnOk(async t =>
                {
                    var ok = await t.ConfigureAwait(false);
                    return new Result<TOk, TError>(ok);
                })
                .Merge(error => Task.FromResult(new Result<TOk, TError>(error)));
        }

        /// <summary>
        /// Convert a collection of <see cref="Result{TOk,TError}"/> into an <see cref="Result{TOk,TError}"/>
        /// which contains all the items if they were all OK, or all the errors if there were any.
        /// </summary>
        /// <param name="results">Collection of <see cref="Result{TOk,TError}"/> items.</param>
        /// <returns>
        /// A <see cref="Result{TOk,TError}"/> containing all the items if they were all successful,
        /// or all the errors if any weren't.
        /// </returns>
        public static Result<IEnumerable<TOk>, TError> Reduce<TOk, TError>(
            this IEnumerable<Result<TOk, TError>> results)
            where TError : ICombinable<TError>
        {
            return results.Aggregate(
                new Result<IEnumerable<TOk>, TError>(Enumerable.Empty<TOk>()),
                (result, either) =>
                    result
                        .With(either)
                        .OnOk(combined => combined.First.Append(combined.Second)));
        }
    }
}
