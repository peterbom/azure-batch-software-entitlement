using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Common
{
    /// <summary>
    /// Extension methods for working with <see cref="Errorable{T}"/>
    /// </summary>
    public static class ErrorableExtensions
    {
        public static Errorable<TResult> Select<TSource, TResult>(
            this Errorable<TSource> source,
            Func<TSource, TResult> selector)
            => source.Then(selector);

        public static Errorable<TResult> SelectMany<TSource, TResult>(
            this Errorable<TSource> source,
            Func<TSource, Errorable<TResult>> selector)
            => source.Then(selector);

        public static Errorable<TResult> SelectMany<TSource, TOther, TResult>(
            this Errorable<TSource> source,
            Func<TSource, Errorable<TOther>> otherSelector,
            Func<TSource, TOther, TResult> resultSelector)
            => source.Then(s => otherSelector(s).Then(o => resultSelector(s, o)));

        /// <summary>
        /// Convert a collection of <see cref="Errorable{T}"/> into an <see cref="Errorable{IEnumerable{T}}"/>
        /// which contains all the items if they were all successful, or all the errors if any weren't.
        /// </summary>
        /// <typeparam name="T">Type of the <see cref="Errorable"/> values.</typeparam>
        /// <param name="errorables">Collection of <see cref="Errorable{T}"/> items.</param>
        /// <returns>
        /// An <see cref="Errorable{IEnumerable{T}}"/> containing all the items if they were all successful,
        /// or all the errors if any weren't.
        /// </returns>
        public static Errorable<IEnumerable<T>> Reduce<T>(this IEnumerable<Errorable<T>> errorables)
        {
            return errorables.Aggregate(
                Errorable.Success(Enumerable.Empty<T>()),
                (result, errorable)
                    => from ts in result
                       from t in errorable
                       select ts.Append(t));
        }
    }
}
